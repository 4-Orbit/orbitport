package account

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type staticTokens struct {
	value string
	err   error
	// The token served after invalidate(), so a test can tell the retry apart.
	rotated      string
	invalidCalls int
}

func (s *staticTokens) token(context.Context) (string, error) { return s.value, s.err }

func (s *staticTokens) invalidate() {
	s.invalidCalls++
	if s.rotated != "" {
		s.value = s.rotated
	}
}

func newTestClient(t *testing.T, handler http.Handler) (*dashboardClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	cfg := &accountConfig{
		DashboardURL:    srv.URL,
		HTTPTimeoutSecs: 5,
	}
	return newDashboardClient(cfg, &staticTokens{value: "test-token"}), srv
}

func TestDashboardClient_Hold_Success(t *testing.T) {
	var capturedAuth string
	var capturedPath string
	var capturedBody holdRequestBody

	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedBody)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ledgerId":"ledger-abc","balance":42,"kmsTenant":"acct-1"}`))
	}))
	defer srv.Close()

	held, err := client.Hold(context.Background(), "client-x", 2, "kms.Sign:ED25519", "pat-jti-1")
	require.NoError(t, err)
	require.Equal(t, "ledger-abc", held.LedgerID)
	require.Equal(t, int64(42), held.Balance)
	require.Equal(t, "acct-1", held.KmsTenant)
	require.Equal(t, "Bearer test-token", capturedAuth)
	require.Equal(t, "/service/credits/hold", capturedPath)
	require.Equal(t, "client-x", capturedBody.ClientID)
	require.Equal(t, uint32(2), capturedBody.Units)
	require.Equal(t, "kms.Sign:ED25519", capturedBody.Operation)
	require.Equal(t, "pat-jti-1", capturedBody.Jti)
}

func TestDashboardClient_Hold_Accepts201(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ledgerId":"ledger-201","balance":7}`))
	}))
	defer srv.Close()

	held, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "")
	require.NoError(t, err)
	require.Equal(t, "ledger-201", held.LedgerID)
	require.Equal(t, int64(7), held.Balance)
}

func TestDashboardClient_Release_Accepts201(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"balance":11}`))
	}))
	defer srv.Close()

	balance, err := client.Release(context.Background(), "ledger-abc")
	require.NoError(t, err)
	require.Equal(t, int64(11), balance)
}

func TestDashboardClient_Hold_InsufficientCredits(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"INSUFFICIENT_CREDITS","message":"out of credits"}`))
	}))
	defer srv.Close()

	_, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "")
	require.ErrorIs(t, err, ErrInsufficientCredits)
}

func TestDashboardClient_Hold_AccountInactive(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"ACCOUNT_INACTIVE","message":"Account is not active"}`))
	}))
	defer srv.Close()

	_, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "jti-1")
	require.ErrorIs(t, err, ErrAccountInactive)
}

func TestDashboardClient_Hold_OtherErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", http.StatusInternalServerError, `{"error":"boom"}`},
		{"401", http.StatusUnauthorized, ``},
		{"422_other_code", http.StatusUnprocessableEntity, `{"code":"OTHER"}`},
		{"403_no_code", http.StatusForbidden, `{"message":"nope"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "")
			require.Error(t, err)
			require.False(t, errors.Is(err, ErrInsufficientCredits))
			require.False(t, errors.Is(err, ErrAccountInactive))
		})
	}
}

func TestDashboardClient_Settle_Success(t *testing.T) {
	var capturedPath string
	var capturedMethod string

	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"balance":42}`))
	}))
	defer srv.Close()

	balance, err := client.Settle(context.Background(), "ledger-abc")
	require.NoError(t, err)
	require.Equal(t, int64(42), balance)
	require.Equal(t, http.MethodPost, capturedMethod)
	require.Equal(t, "/service/credits/hold/ledger-abc/settle", capturedPath)
}

func TestDashboardClient_Settle_Accepts201(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"balance":7}`))
	}))
	defer srv.Close()

	balance, err := client.Settle(context.Background(), "ledger-abc")
	require.NoError(t, err)
	require.Equal(t, int64(7), balance)
}

func TestDashboardClient_Settle_Error(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := client.Settle(context.Background(), "ledger-abc")
	require.Error(t, err)
}

func TestDashboardClient_Release_Success(t *testing.T) {
	var capturedPath string

	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"balance":43}`))
	}))
	defer srv.Close()

	balance, err := client.Release(context.Background(), "ledger-abc")
	require.NoError(t, err)
	require.Equal(t, int64(43), balance)
	require.Equal(t, "/service/credits/hold/ledger-abc/release", capturedPath)
}

func TestDashboardClient_Release_Error(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := client.Release(context.Background(), "ledger-abc")
	require.Error(t, err)
}

func TestDashboardClient_NoToken_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("should not reach server when token is missing")
	}))
	defer srv.Close()

	cfg := &accountConfig{DashboardURL: srv.URL, HTTPTimeoutSecs: 5}
	client := newDashboardClient(cfg, &staticTokens{err: errors.New("no token")})

	_, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "")
	require.Error(t, err)
}

// A 401 means the cached M2M token was rejected regardless of its claimed
// expiry, so the client must drop it and retry once with a fresh one.
func TestDashboardClient_Hold_RetriesOnceAfter401(t *testing.T) {
	var seenAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = append(seenAuth, r.Header.Get("Authorization"))
		if len(seenAuth) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Invalid or missing access token"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ledgerId":"ledger-retry","balance":7}`))
	}))
	defer srv.Close()

	tokens := &staticTokens{value: "stale-token", rotated: "fresh-token"}
	cfg := &accountConfig{DashboardURL: srv.URL, HTTPTimeoutSecs: 5}
	client := newDashboardClient(cfg, tokens)

	held, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "jti-1")
	require.NoError(t, err)
	require.Equal(t, "ledger-retry", held.LedgerID)
	require.Equal(t, int64(7), held.Balance)
	require.Equal(t, 1, tokens.invalidCalls)
	require.Equal(t, []string{"Bearer stale-token", "Bearer fresh-token"}, seenAuth)
}

// The retry is once, not a loop: a persistently rejecting dashboard must
// surface an error rather than spin.
func TestDashboardClient_Hold_401RetryHappensOnce(t *testing.T) {
	var calls int
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "")
	require.Error(t, err)
	require.Equal(t, 2, calls)
}

// 404 is the PAT revocation path and must stay a distinguishable client error,
// never folded into a generic transport failure.
func TestDashboardClient_Hold_404IsUnknownCredential(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	_, err := client.Hold(context.Background(), "client-x", 1, "kms.Sign:ED25519", "revoked-jti")
	require.ErrorIs(t, err, ErrUnknownCredential)
}

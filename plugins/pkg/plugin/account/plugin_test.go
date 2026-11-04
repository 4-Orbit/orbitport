package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newTestPlugin(t *testing.T, handler http.HandlerFunc) (*Plugin, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	cfg := &accountConfig{
		DashboardURL:      srv.URL,
		Auth0Domain:       "auth0.example.com",
		Auth0Audience:     "https://api.example.com",
		Auth0ClientID:     "cid",
		Auth0ClientSecret: "secret",
		CreditsPerUnit:    1,
		HTTPTimeoutSecs:   5,
	}
	tokens := &staticTokens{value: "test-token"}
	return &Plugin{
		cfg:    cfg,
		client: newDashboardClient(cfg, tokens),
		logger: utils.GetLogger("orbitport:account:test"),
	}, srv
}

func TestPlugin_Hold_Success(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ledgerId":"ledger-1","balance":99}`))
	})
	defer srv.Close()

	resp, err := plugin.Hold(context.Background(), &proto.HoldRequest{
		ClientId: "client-1", Units: 1, Operation: "kms.Sign:ED25519",
	})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, "ledger-1", resp.LedgerId)
	require.Equal(t, int64(99), resp.BalanceAfter)
}

func TestPlugin_Hold_InsufficientCreditsMapsToFailedPrecondition(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"INSUFFICIENT_CREDITS","message":"out"}`))
	})
	defer srv.Close()

	resp, err := plugin.Hold(context.Background(), &proto.HoldRequest{
		ClientId: "client-1", Units: 1, Operation: "kms.Sign:ED25519",
	})
	require.Error(t, err)
	require.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.Equal(t, "insufficient_credits", st.Message())
}

func TestPlugin_Hold_AccountInactiveMapsToPermissionDenied(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"ACCOUNT_INACTIVE","message":"Account is not active"}`))
	})
	defer srv.Close()

	resp, err := plugin.Hold(context.Background(), &proto.HoldRequest{
		ClientId: "client-1", Units: 1, Operation: "kms.Sign:ED25519",
	})
	require.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Equal(t, "account_inactive", st.Message())
}

func TestPlugin_Hold_TransportFailureMapsToUnavailable(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	_, err := plugin.Hold(context.Background(), &proto.HoldRequest{
		ClientId: "client-1", Units: 1, Operation: "kms.Sign:ED25519",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code())
}

func TestPlugin_Hold_MissingClientID(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("should not reach dashboard")
	})
	defer srv.Close()

	_, err := plugin.Hold(context.Background(), &proto.HoldRequest{ClientId: ""})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
}

func TestPlugin_Release_Success(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"balance":100}`))
	})
	defer srv.Close()

	resp, err := plugin.Release(context.Background(), &proto.ReleaseRequest{LedgerId: "lg"})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, int64(100), resp.BalanceAfter)
}

func TestPlugin_Release_FailureMapsToUnavailable(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	_, err := plugin.Release(context.Background(), &proto.ReleaseRequest{LedgerId: "lg"})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.Unavailable, st.Code())
}

func TestPlugin_Release_MissingLedger(t *testing.T) {
	plugin, _ := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {})

	_, err := plugin.Release(context.Background(), &proto.ReleaseRequest{LedgerId: ""})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
}

func TestPlugin_Settle_Success(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/service/credits/hold/lg/settle", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"balance":88}`))
	})
	defer srv.Close()

	resp, err := plugin.Settle(context.Background(), &proto.SettleRequest{LedgerId: "lg"})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, int64(88), resp.BalanceAfter)
}

func TestPlugin_Settle_FailureMapsToUnavailable(t *testing.T) {
	plugin, srv := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	_, err := plugin.Settle(context.Background(), &proto.SettleRequest{LedgerId: "lg"})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.Unavailable, st.Code())
}

func TestPlugin_Settle_MissingLedger(t *testing.T) {
	plugin, _ := newTestPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("should not reach dashboard")
	})

	_, err := plugin.Settle(context.Background(), &proto.SettleRequest{LedgerId: ""})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
}

func TestConfig_ValidateMissingRequired(t *testing.T) {
	cfg := &accountConfig{CreditsPerUnit: 1, HTTPTimeoutSecs: 5}
	require.Error(t, cfg.validate())
}

func TestConfig_ValidateOK(t *testing.T) {
	cfg := &accountConfig{
		DashboardURL:      "https://x",
		Auth0Domain:       "d",
		Auth0Audience:     "a",
		Auth0ClientID:     "c",
		Auth0ClientSecret: "s",
		CreditsPerUnit:    1,
		HTTPTimeoutSecs:   5,
	}
	require.NoError(t, cfg.validate())
}

package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
)

// ErrInsufficientCredits is returned by dashboardClient.Hold when the
// dashboard responds with HTTP 422 + code=INSUFFICIENT_CREDITS.
var ErrInsufficientCredits = errors.New("insufficient_credits")

// ErrUnknownCredential is returned by dashboardClient.Hold on a 404: an
// unknown, revoked, or expired credential. This is the PAT revocation path,
// an auth failure and never a plugin outage.
var ErrUnknownCredential = errors.New("unknown_or_revoked_credential")

// ErrAccountInactive is returned by dashboardClient.Hold when the dashboard
// responds with HTTP 403 + code=ACCOUNT_INACTIVE (suspended account).
var ErrAccountInactive = errors.New("account_inactive")

// dashboardClient is a typed HTTP wrapper around the dashboard backend's
// service credit endpoints. It attaches an Auth0 M2M bearer token on every
// request and applies a per-request timeout.
type dashboardClient struct {
	baseURL    string
	httpClient *http.Client
	tokens     tokenProvider
	logger     *utils.Logger
}

// tokenProvider is the subset of tokenManager the dashboard client depends on.
// Lets tests inject a static token without standing up an Auth0 mock.
type tokenProvider interface {
	token(ctx context.Context) (string, error)
	invalidate()
}

type holdRequestBody struct {
	ClientID  string `json:"clientId"`
	Units     uint32 `json:"units"`
	Operation string `json:"operation,omitempty"`
	// Non-empty = the request was authenticated with a PAT.
	Jti string `json:"jti,omitempty"`
}

type holdResponseBody struct {
	LedgerID string `json:"ledgerId"`
	Balance  int64  `json:"balance"`
	// Empty from a dashboard predating this field; the gateway handles that.
	KmsTenant string `json:"kmsTenant"`
}

type settleResponseBody struct {
	Balance int64 `json:"balance"`
}

type releaseResponseBody struct {
	Balance int64 `json:"balance"`
}

type dashboardErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newDashboardClient(cfg *accountConfig, tokens tokenProvider) *dashboardClient {
	return &dashboardClient{
		baseURL: strings.TrimRight(cfg.DashboardURL, "/"),
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.HTTPTimeoutSecs) * time.Second,
		},
		tokens: tokens,
		logger: utils.GetLogger("orbitport:account:dashboard"),
	}
}

// do sends a dashboard request and reads the full response. On a 401 the
// cached M2M token is dropped and the request retried once with a fresh one.
func (d *dashboardClient) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	status, rawBody, err := d.send(ctx, method, path, body)
	if err != nil || status != http.StatusUnauthorized {
		return status, rawBody, err
	}

	d.logger.Warn("dashboard rejected the M2M token (401); refreshing and retrying once")
	d.tokens.invalidate()
	return d.send(ctx, method, path, body)
}

func (d *dashboardClient) send(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	req, err := d.newRequest(ctx, method, path, body)
	if err != nil {
		return 0, nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	rawBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, rawBody, nil
}

// Hold posts to /service/credits/hold. Returns ErrInsufficientCredits on 422,
// ErrAccountInactive on 403 ACCOUNT_INACTIVE, ErrUnknownCredential on 404,
// or a wrapped transport error on any other non-2xx.
func (d *dashboardClient) Hold(ctx context.Context, clientID string, units uint32, operation, jti string) (holdResponseBody, error) {
	var empty holdResponseBody
	body, err := json.Marshal(holdRequestBody{ClientID: clientID, Units: units, Operation: operation, Jti: jti})
	if err != nil {
		return empty, fmt.Errorf("marshal hold request: %w", err)
	}

	status, rawBody, err := d.do(ctx, http.MethodPost, "/service/credits/hold", body)
	if err != nil {
		return empty, fmt.Errorf("dashboard hold transport error: %w", err)
	}

	switch status {
	case http.StatusOK, http.StatusCreated:
		var parsed holdResponseBody
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return empty, fmt.Errorf("decode hold response: %w", err)
		}
		if parsed.LedgerID == "" {
			return empty, fmt.Errorf("dashboard hold response missing ledgerId")
		}
		return parsed, nil
	case http.StatusUnprocessableEntity:
		var parsed dashboardErrorBody
		_ = json.Unmarshal(rawBody, &parsed)
		if parsed.Code == "INSUFFICIENT_CREDITS" {
			return empty, ErrInsufficientCredits
		}
		return empty, fmt.Errorf("dashboard hold rejected (422): %s", strings.TrimSpace(string(rawBody)))
	case http.StatusForbidden:
		var parsed dashboardErrorBody
		_ = json.Unmarshal(rawBody, &parsed)
		if parsed.Code == "ACCOUNT_INACTIVE" {
			return empty, ErrAccountInactive
		}
		return empty, fmt.Errorf("dashboard hold rejected (403): %s", strings.TrimSpace(string(rawBody)))
	case http.StatusNotFound:
		return empty, ErrUnknownCredential
	default:
		return empty, fmt.Errorf("dashboard hold returned %d: %s", status, strings.TrimSpace(string(rawBody)))
	}
}

// Settle posts to /service/credits/hold/:ledgerId/settle. It commits a hold so
// the dashboard sweeper no longer treats it as an orphan to refund; the balance
// is unchanged (the hold already deducted). 4xx/5xx responses are returned as
// errors so callers can distinguish "tried" from "ok". The endpoint is
// idempotent on the backend.
func (d *dashboardClient) Settle(ctx context.Context, ledgerID string) (int64, error) {
	path := "/service/credits/hold/" + ledgerID + "/settle"
	status, rawBody, err := d.do(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("dashboard settle transport error: %w", err)
	}

	if status != http.StatusOK && status != http.StatusCreated {
		return 0, fmt.Errorf("dashboard settle returned %d: %s", status, strings.TrimSpace(string(rawBody)))
	}

	var parsed settleResponseBody
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return 0, fmt.Errorf("decode settle response: %w", err)
	}
	return parsed.Balance, nil
}

// Release posts to /service/credits/hold/:ledgerId/release. 4xx responses are
// logged and returned as errors so callers can distinguish "tried" from "ok".
// The endpoint is idempotent on the backend.
func (d *dashboardClient) Release(ctx context.Context, ledgerID string) (int64, error) {
	path := "/service/credits/hold/" + ledgerID + "/release"
	status, rawBody, err := d.do(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, fmt.Errorf("dashboard release transport error: %w", err)
	}

	if status != http.StatusOK && status != http.StatusCreated {
		return 0, fmt.Errorf("dashboard release returned %d: %s", status, strings.TrimSpace(string(rawBody)))
	}

	var parsed releaseResponseBody
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return 0, fmt.Errorf("decode release response: %w", err)
	}
	return parsed.Balance, nil
}

func (d *dashboardClient) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	var req *http.Request
	var err error
	if reader != nil {
		req, err = http.NewRequestWithContext(ctx, method, d.baseURL+path, reader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, d.baseURL+path, http.NoBody)
	}
	if err != nil {
		return nil, fmt.Errorf("build dashboard request: %w", err)
	}

	token, err := d.tokens.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("attach M2M token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

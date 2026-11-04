package account

import (
	"context"
	"errors"
	"fmt"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sentinelInsufficient is the value written to HoldResponse.Error when the
// dashboard reports the account is out of credits. The gateway maps this
// sentinel to HTTP 402.
const sentinelInsufficient = "insufficient_credits"

// Plugin implements the AccountPluginServer interface. It translates gRPC
// Hold/Release calls into HTTP calls against the dashboard backend.
type Plugin struct {
	proto.UnimplementedAccountPluginServer

	cfg    *accountConfig
	tokens *tokenManager
	client *dashboardClient
	logger *utils.Logger
}

// NewPlugin creates and starts the Account plugin. Fail-closed: refuses to
// start when required env vars are missing or the initial M2M token fetch
// fails.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	logger := utils.GetLogger("orbitport:account")
	logger.Infof(
		"creating account plugin with dashboard_url=%s, auth0_domain=%s, credits_per_unit=%d, http_timeout_secs=%d",
		cfg.DashboardURL,
		cfg.Auth0Domain,
		cfg.CreditsPerUnit,
		cfg.HTTPTimeoutSecs,
	)

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	tokens := newTokenManager(cfg)
	if err := tokens.start(context.Background()); err != nil {
		return nil, fmt.Errorf("account plugin: %w", err)
	}

	return &Plugin{
		cfg:    cfg,
		tokens: tokens,
		client: newDashboardClient(cfg, tokens),
		logger: logger,
	}, nil
}

// Close releases plugin resources. The token manager refreshes on demand and
// holds no background goroutines, so there is nothing to tear down today; the
// method is retained for the plugin host lifecycle. Safe to call multiple times.
func (p *Plugin) Close() {}

// Hold deducts credits via the dashboard /service/credits/hold endpoint.
// Returns gRPC codes.FailedPrecondition with HoldResponse.Error="insufficient_credits"
// when the dashboard reports the account is out of credits;
// codes.PermissionDenied "account_inactive" for a suspended account; codes.Unavailable
// on any other transport failure.
func (p *Plugin) Hold(ctx context.Context, req *proto.HoldRequest) (*proto.HoldResponse, error) {
	clientID := req.GetClientId()
	if clientID == "" {
		return nil, status.Error(codes.InvalidArgument, "client_id is required")
	}
	units := req.GetUnits()
	if units == 0 {
		units = 1
	}

	credits := units * p.cfg.CreditsPerUnit
	held, err := p.client.Hold(ctx, clientID, credits, req.GetOperation(), req.GetJti())
	if err != nil {
		if errors.Is(err, ErrInsufficientCredits) {
			p.logger.Debugf("hold rejected for client_id=%s op=%s: insufficient credits", clientID, req.GetOperation())
			return nil, status.Error(codes.FailedPrecondition, sentinelInsufficient)
		}
		if errors.Is(err, ErrAccountInactive) {
			p.logger.Debugf("hold rejected for client_id=%s op=%s: account inactive", clientID, req.GetOperation())
			return nil, status.Error(codes.PermissionDenied, ErrAccountInactive.Error())
		}
		if errors.Is(err, ErrUnknownCredential) {
			p.logger.Debugf("hold rejected for client_id=%s op=%s: unknown or revoked credential", clientID, req.GetOperation())
			return nil, status.Error(codes.PermissionDenied, ErrUnknownCredential.Error())
		}
		p.logger.Warnf("hold failed for client_id=%s op=%s: %v", clientID, req.GetOperation(), err)
		return nil, status.Error(codes.Unavailable, err.Error())
	}

	p.logger.Debugf("hold ok for client_id=%s op=%s ledger_id=%s balance_after=%d", clientID, req.GetOperation(), held.LedgerID, held.Balance)
	return &proto.HoldResponse{
		Ok:           true,
		LedgerId:     held.LedgerID,
		BalanceAfter: held.Balance,
		KmsTenant:    held.KmsTenant,
	}, nil
}

// Settle commits a previous hold so the dashboard sweeper no longer treats it
// as an orphan to refund. Idempotent on the backend; the balance is unchanged
// (the hold already deducted). Transport failures map to codes.Unavailable; the
// gateway logs + ignores settle errors and lets the dashboard sweeper backstop
// genuinely orphaned holds.
func (p *Plugin) Settle(ctx context.Context, req *proto.SettleRequest) (*proto.SettleResponse, error) {
	ledgerID := req.GetLedgerId()
	if ledgerID == "" {
		return nil, status.Error(codes.InvalidArgument, "ledger_id is required")
	}

	balance, err := p.client.Settle(ctx, ledgerID)
	if err != nil {
		p.logger.Warnf("settle failed for ledger_id=%s: %v", ledgerID, err)
		return nil, status.Error(codes.Unavailable, err.Error())
	}

	p.logger.Debugf("settle ok for ledger_id=%s balance_after=%d", ledgerID, balance)
	return &proto.SettleResponse{
		Ok:           true,
		BalanceAfter: balance,
	}, nil
}

// Release refunds a previous hold. Idempotent on the backend. Transport
// failures map to codes.Unavailable; the gateway logs + ignores release
// errors and lets the dashboard sweeper backstop genuinely orphaned holds.
func (p *Plugin) Release(ctx context.Context, req *proto.ReleaseRequest) (*proto.ReleaseResponse, error) {
	ledgerID := req.GetLedgerId()
	if ledgerID == "" {
		return nil, status.Error(codes.InvalidArgument, "ledger_id is required")
	}

	balance, err := p.client.Release(ctx, ledgerID)
	if err != nil {
		p.logger.Warnf("release failed for ledger_id=%s: %v", ledgerID, err)
		return nil, status.Error(codes.Unavailable, err.Error())
	}

	p.logger.Debugf("release ok for ledger_id=%s balance_after=%d", ledgerID, balance)
	return &proto.ReleaseResponse{
		Ok:           true,
		BalanceAfter: balance,
	}, nil
}

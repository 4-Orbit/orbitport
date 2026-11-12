package patissuer

import (
	"context"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Plugin mints Personal Access Tokens and serves the public JWKS. The
// dashboard owns the PAT metadata row (jti) and the charge flow.
type Plugin struct {
	proto.UnimplementedPatIssuerPluginServer

	cfg    *patissuerConfig
	signer signer
	logger *utils.Logger
}

// Same identifier shape as the Cedar engine's agent ids.
var agentIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	logger := utils.GetLogger("orbitport:issuer")

	if cfg.Signer == signerTransit {
		logger.Infof(
			"transit signer: %s (mount=%s key=%s) — the OpenBao proxy owns auth",
			cfg.OpenBaoProxyURL, cfg.TransitMount, cfg.TransitKey,
		)
		return &Plugin{cfg: cfg, signer: newTransitSigner(cfg), logger: logger}, nil
	}

	s, generated, err := newLocalSigner(cfg.LocalKeyPEM)
	if err != nil {
		return nil, err
	}
	if generated {
		logger.Warn(
			"ORBITPORT_PATISSUER_LOCAL_KEY_PEM not set — generated an EPHEMERAL signing key; " +
				"every restart invalidates all outstanding PATs. Dev only, never production.",
		)
	}

	return &Plugin{cfg: cfg, signer: s, logger: logger}, nil
}

func (p *Plugin) IssueToken(ctx context.Context, req *proto.IssueTokenRequest) (*proto.IssueTokenResponse, error) {
	if req.GetJti() == "" {
		return nil, status.Error(codes.InvalidArgument, "jti is required")
	}
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	now := time.Now()
	exp := time.Unix(req.GetExpiresAt(), 0)
	if !exp.After(now) {
		return nil, status.Error(codes.InvalidArgument, "expires_at must be in the future")
	}
	if agentID := req.GetAgentId(); agentID != "" {
		if !agentIDRe.MatchString(agentID) {
			return nil, status.Error(codes.InvalidArgument, "agent_id must be 1-64 characters of a-z, 0-9, - or _")
		}
		lifetime := exp.Sub(now)
		if minTTL := time.Duration(p.cfg.AgentMinTTLSecs) * time.Second; lifetime < minTTL {
			return nil, status.Errorf(codes.InvalidArgument, "agent token lifetime must be at least %d seconds", p.cfg.AgentMinTTLSecs)
		}
		if maxTTL := time.Duration(p.cfg.AgentMaxTTLSecs) * time.Second; maxTTL > 0 && lifetime > maxTTL+time.Second {
			return nil, status.Errorf(codes.InvalidArgument, "agent token lifetime exceeds %d seconds", p.cfg.AgentMaxTTLSecs)
		}
	}
	if exp.After(now.AddDate(0, 0, p.cfg.MaxTTLDays)) {
		return nil, status.Errorf(codes.InvalidArgument, "expires_at exceeds the %d-day ceiling", p.cfg.MaxTTLDays)
	}

	claims := jwt.MapClaims{
		"iss": p.cfg.Issuer,
		"aud": p.cfg.Audience,
		"sub": req.GetSubject(),
		"jti": req.GetJti(),
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}
	if req.GetKmsTenant() != "" {
		claims["kms_tenant"] = req.GetKmsTenant()
	}
	if req.GetAgentId() != "" {
		claims["agent_id"] = req.GetAgentId()
	}

	token, err := p.signer.Mint(ctx, claims)
	if err != nil {
		p.logger.Errorf("signing PAT jti=%s failed: %v", req.GetJti(), err)
		return nil, status.Error(codes.Internal, "signing failed")
	}

	// No jti or sub. This line lands in pod logs, and the pair is enough to
	// forge a usable PAT for a real account against the unauthenticated mint
	// RPC. The dashboard owns the PAT row if you need to trace one.
	p.logger.Infof("issued PAT exp=%s", exp.UTC().Format(time.RFC3339))

	return &proto.IssueTokenResponse{Ok: true, Token: token}, nil
}

func (p *Plugin) GetJwks(ctx context.Context, _ *proto.GetJwksRequest) (*proto.GetJwksResponse, error) {
	jwks, err := p.signer.JWKS(ctx)
	if err != nil {
		p.logger.Errorf("building JWKS failed: %v", err)
		return nil, status.Error(codes.Internal, "building JWKS failed")
	}
	return &proto.GetJwksResponse{JwksJson: jwks}, nil
}

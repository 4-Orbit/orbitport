package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

var errAuth0JWKSUnavailable = errors.New("Auth0 JWKS unavailable")

// Plugin implements the AuthPluginServer interface for the Auth0 API.
type Plugin struct {
	proto.AuthPluginServer

	jwtValidator    *validator.Validator
	cachingProvider *jwks.CachingProvider

	// patKeys is nil when PAT validation is not configured.
	patIss           string
	patAudience      string
	patKeys          *jwksCache
	serviceClientIDs map[string]struct{}
}

type serviceClaims struct {
	Scope     string `json:"scope"`
	GrantType string `json:"gty"`
}

func (*serviceClaims) Validate(context.Context) error {
	return nil
}

func (c *serviceClaims) hasRequiredScopes(requiredScopes []string) bool {
	scopes := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range strings.Fields(c.Scope) {
		scopes[scope] = struct{}{}
	}
	for _, scope := range requiredScopes {
		if _, ok := scopes[scope]; !ok {
			return false
		}
	}
	return true
}

func (c *serviceClaims) hasClientCredentialsGrant() bool {
	return c.GrantType == "client-credentials"
}

// NewPlugin creates a new Auth plugin.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	logger := utils.GetLogger("orbitport:auth")
	logger.Infof("creating plugin with config: %+v", cfg)

	// strict fail-closed validation
	if len(cfg.Auth0Domain) == 0 || len(cfg.Auth0Audience) == 0 {
		return nil, fmt.Errorf("FATAL: Auth0Domain or Auth0Audience is missing. Refusing to start without auth configuration")
	}

	// fail-closed on partial PAT configuration
	if err := cfg.validatePat(); err != nil {
		return nil, err
	}

	logger.Debug("Auth0 domain is set, creating Auth plugin")
	plugin, err := newAuthPlugin(cfg.Auth0Domain, cfg.Auth0Audience)
	if err != nil {
		return nil, fmt.Errorf("failed to create Auth plugin: %w", err)
	}
	plugin.serviceClientIDs = cfg.serviceClientIDSet()
	logger.Info("authentication is ON")

	if cfg.patEnabled() {
		cache, err := newJWKSCache(cfg.PatIssuerPlugin)
		if err != nil {
			return nil, fmt.Errorf("failed to create PAT JWKS cache: %w", err)
		}
		plugin.patIss = cfg.PatIss
		plugin.patAudience = cfg.PatAudience
		if plugin.patAudience == "" {
			plugin.patAudience = cfg.Auth0Audience
		}
		plugin.patKeys = cache
		logger.Infof("PAT validation is ON (iss=%s)", cfg.PatIss)
	} else {
		logger.Warn("PAT config is absent: ValidateToken will refuse every customer token")
	}

	return plugin, nil
}

func newAuthPlugin(auth0Domain, auth0Audience string) (*Plugin, error) {
	issuerURL, err := url.Parse("https://" + auth0Domain + "/")
	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	cProvider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		wrapAuth0KeyFunc(cProvider.KeyFunc),
		validator.RS256,
		issuerURL.String(),
		[]string{auth0Audience},
		validator.WithAllowedClockSkew(time.Minute),
		validator.WithCustomClaims(func() validator.CustomClaims {
			return &serviceClaims{}
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the jwt validator: %w", err)
	}

	plugin := new(Plugin)
	plugin.jwtValidator = jwtValidator
	plugin.cachingProvider = cProvider

	return plugin, nil
}

// ValidateToken handles the ValidateToken RPC call. Only PATs authenticate
// customers; every PAT carries a non-empty Jti.
func (p *Plugin) ValidateToken(ctx context.Context, req *proto.TokenValidationRequest) (*proto.TokenValidationResponse, error) {
	logger := utils.GetLogger("orbitport:auth")
	logger.Debug("Validating token")
	if p.patKeys == nil || unverifiedIssuer(req.Token) != p.patIss {
		return nil, status.Error(codes.Unauthenticated, "invalid_credential: not a personal access token")
	}
	resp, err := p.validatePAT(ctx, req.Token)
	if err != nil {
		logger.Warnf("Encountered error while validating PAT: %v", err)
		return nil, err
	}
	return resp, nil
}

// ValidateServiceToken authorizes an Auth0 M2M client for a gateway-internal
// capability. It intentionally does not accept user JWTs or PATs.
func (p *Plugin) ValidateServiceToken(
	ctx context.Context,
	req *proto.ServiceTokenValidationRequest,
) (*proto.ServiceTokenValidationResponse, error) {
	// A service token authorizes one named capability. An empty list satisfies
	// the scope check vacuously, so a route that forgets to name its scope
	// fails closed instead of authorizing every allowlisted client.
	if len(req.GetRequiredScopes()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "required_scopes must not be empty")
	}

	validatedClaims, err := p.validateAuth0Token(ctx, req.GetToken())
	if err != nil {
		if errors.Is(err, errAuth0JWKSUnavailable) {
			return nil, status.Error(codes.Unavailable, "Auth0 JWKS unavailable")
		}
		return nil, status.Error(codes.Unauthenticated, "invalid service token")
	}
	if validatedClaims.RegisteredClaims.Expiry <= 0 {
		return nil, status.Error(codes.Unauthenticated, "invalid service token")
	}

	clientID, isM2M := strings.CutSuffix(validatedClaims.RegisteredClaims.Subject, "@clients")
	if !isM2M || clientID == "" {
		return nil, status.Error(codes.PermissionDenied, "service token is not authorized")
	}
	if _, ok := p.serviceClientIDs[clientID]; !ok {
		return nil, status.Error(codes.PermissionDenied, "service token is not authorized")
	}

	claims, ok := validatedClaims.CustomClaims.(*serviceClaims)
	if !ok || !claims.hasClientCredentialsGrant() || !claims.hasRequiredScopes(req.GetRequiredScopes()) {
		return nil, status.Error(codes.PermissionDenied, "service token is not authorized")
	}

	return &proto.ServiceTokenValidationResponse{
		Ok:       true,
		ClientId: clientID,
	}, nil
}

func (p *Plugin) validateAuth0Token(ctx context.Context, token string) (*validator.ValidatedClaims, error) {
	claims, err := p.jwtValidator.ValidateToken(ctx, token)
	if err != nil {
		return nil, err
	}
	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected validated claims type %T", claims)
	}
	return validatedClaims, nil
}

func wrapAuth0KeyFunc(
	keyFunc func(context.Context) (interface{}, error),
) func(context.Context) (interface{}, error) {
	return func(ctx context.Context) (interface{}, error) {
		key, err := keyFunc(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errAuth0JWKSUnavailable, err)
		}
		return key, nil
	}
}

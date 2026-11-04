package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	auth0validator "github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const (
	testAuth0Iss = "https://auth0.orbitport.test/"
	testPatIss   = "https://auth.orbitport.test"
	testPatAud   = "https://api.orbitport.test"
)

// mockIssuer is an in-process gRPC patissuer plugin serving a swappable JWKS.
type mockIssuer struct {
	proto.UnimplementedPatIssuerPluginServer

	mu    sync.Mutex
	jwks  string
	calls int
}

func (m *mockIssuer) GetJwks(context.Context, *proto.GetJwksRequest) (*proto.GetJwksResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return &proto.GetJwksResponse{JwksJson: m.jwks}, nil
}

func (m *mockIssuer) setJWKS(jwks string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwks = jwks
}

func (m *mockIssuer) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func startMockIssuer(t *testing.T, m *mockIssuer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterPatIssuerPluginServer(srv, m)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func jwksJSON(kid string, pub *ecdsa.PublicKey) string {
	b, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	x, y := b[1:33], b[33:]
	return fmt.Sprintf(
		`{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":%q,"x":%q,"y":%q}]}`,
		kid,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y),
	)
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func patClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":        testPatIss,
		"aud":        testPatAud,
		"sub":        "acct-1",
		"jti":        "pat-jti-1",
		"kms_tenant": "tenant-1",
		"iat":        now.Unix(),
		"exp":        now.Add(time.Hour).Unix(),
	}
}

func mintES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// newTestPlugin points the PAT path at the in-process issuer mock. The Auth0
// domain is a dead hostname.
func newTestPlugin(t *testing.T, issuerAddr string) *Plugin {
	t.Helper()
	viper.Reset()
	t.Setenv("ORBITPORT_AUTH0_DOMAIN", "auth0.invalid")
	t.Setenv("ORBITPORT_AUTH0_AUDIENCE", testPatAud)
	t.Setenv("ORBITPORT_AUTH_PAT_ISS", testPatIss)
	t.Setenv("ORBITPORT_AUTH_PAT_AUDIENCE", testPatAud)
	t.Setenv("ORBITPORT_AUTH_PATISSUER_PLUGIN", issuerAddr)
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	p, err := NewPlugin()
	require.NoError(t, err)
	return p
}

func newServiceTestPlugin(t *testing.T) (*Plugin, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwtValidator, err := auth0validator.New(
		wrapAuth0KeyFunc(func(context.Context) (interface{}, error) { return &key.PublicKey, nil }),
		auth0validator.RS256,
		testAuth0Iss,
		[]string{testPatAud},
		auth0validator.WithCustomClaims(func() auth0validator.CustomClaims {
			return &serviceClaims{}
		}),
	)
	require.NoError(t, err)

	return &Plugin{
		jwtValidator:     jwtValidator,
		serviceClientIDs: map[string]struct{}{"dashboard-service": {}},
	}, key
}

func mintServiceToken(t *testing.T, key *rsa.PrivateKey, subject, scope string) string {
	return mintServiceTokenWithClaims(t, key, testAuth0Iss, testPatAud, subject, scope, time.Now().Add(time.Hour))
}

func mintServiceTokenWithClaims(
	t *testing.T,
	key *rsa.PrivateKey,
	issuer, audience, subject, scope string,
	expiresAt time.Time,
) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"aud":   audience,
		"sub":   subject,
		"scope": scope,
		"gty":   "client-credentials",
		"iat":   time.Now().Unix(),
		"exp":   expiresAt.Unix(),
	})
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func mintServiceTokenWithoutExpiration(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   testAuth0Iss,
		"aud":   testPatAud,
		"sub":   "dashboard-service@clients",
		"scope": "pat:issue",
		"gty":   "client-credentials",
		"iat":   time.Now().Unix(),
	})
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func mintServiceTokenWithGrantType(t *testing.T, key *rsa.PrivateKey, grantType string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   testAuth0Iss,
		"aud":   testPatAud,
		"sub":   "dashboard-service@clients",
		"scope": "pat:issue",
		"gty":   grantType,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestValidateServiceToken_RequiresAllowlistedM2MClientAndScope(t *testing.T) {
	p, key := newServiceTestPlugin(t)

	tests := []struct {
		name       string
		subject    string
		scope      string
		wantCode   codes.Code
		wantClient string
	}{
		{
			name:       "allowlisted client with required scope",
			subject:    "dashboard-service@clients",
			scope:      "pat:issue services:read",
			wantCode:   codes.OK,
			wantClient: "dashboard-service",
		},
		{
			name:     "user token is not a service token",
			subject:  "auth0|user-1",
			scope:    "pat:issue",
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "unallowlisted service client",
			subject:  "other-service@clients",
			scope:    "pat:issue",
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "missing required scope",
			subject:  "dashboard-service@clients",
			scope:    "services:read",
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "scope substring does not authorize",
			subject:  "dashboard-service@clients",
			scope:    "pat:issue-other",
			wantCode: codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
				Token:          mintServiceToken(t, key, tt.subject, tt.scope),
				RequiredScopes: []string{"pat:issue"},
			})
			if tt.wantCode != codes.OK {
				st, ok := status.FromError(err)
				require.True(t, ok, "expected gRPC status error, got %v", err)
				require.Equal(t, tt.wantCode, st.Code())
				return
			}

			require.NoError(t, err)
			require.True(t, resp.Ok)
			require.Equal(t, tt.wantClient, resp.ClientId)
		})
	}
}

func TestValidateServiceToken_RejectsInvalidAuth0Tokens(t *testing.T) {
	p, key := newServiceTestPlugin(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed token",
			token: "not-a-jwt",
		},
		{
			name: "wrong issuer",
			token: mintServiceTokenWithClaims(
				t, key, "https://other-auth0.test/", testPatAud, "dashboard-service@clients", "pat:issue", time.Now().Add(time.Hour),
			),
		},
		{
			name: "wrong audience",
			token: mintServiceTokenWithClaims(
				t, key, testAuth0Iss, "https://other-api.test", "dashboard-service@clients", "pat:issue", time.Now().Add(time.Hour),
			),
		},
		{
			name: "expired token",
			token: mintServiceTokenWithClaims(
				t, key, testAuth0Iss, testPatAud, "dashboard-service@clients", "pat:issue", time.Now().Add(-time.Minute),
			),
		},
		{
			name: "invalid signature",
			token: mintServiceTokenWithClaims(
				t, otherKey, testAuth0Iss, testPatAud, "dashboard-service@clients", "pat:issue", time.Now().Add(time.Hour),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
				Token:          tt.token,
				RequiredScopes: []string{"pat:issue"},
			})
			st, ok := status.FromError(err)
			require.True(t, ok, "expected gRPC status error, got %v", err)
			require.Equal(t, codes.Unauthenticated, st.Code())
		})
	}
}

func TestValidateServiceToken_RequiresExpirationAndClientCredentialsGrant(t *testing.T) {
	p, key := newServiceTestPlugin(t)

	tests := []struct {
		name     string
		token    string
		wantCode codes.Code
	}{
		{
			name:     "missing expiration",
			token:    mintServiceTokenWithoutExpiration(t, key),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "missing client credentials grant",
			token:    mintServiceTokenWithGrantType(t, key, ""),
			wantCode: codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
				Token:          tt.token,
				RequiredScopes: []string{"pat:issue"},
			})
			st, ok := status.FromError(err)
			require.True(t, ok, "expected gRPC status error, got %v", err)
			require.Equal(t, tt.wantCode, st.Code())
		})
	}
}

func TestValidateServiceToken_ReportsAuth0JWKSErrorsAsUnavailable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtValidator, err := auth0validator.New(
		wrapAuth0KeyFunc(func(context.Context) (interface{}, error) {
			return nil, errors.New("JWKS request failed")
		}),
		auth0validator.RS256,
		testAuth0Iss,
		[]string{testPatAud},
		auth0validator.WithCustomClaims(func() auth0validator.CustomClaims {
			return &serviceClaims{}
		}),
	)
	require.NoError(t, err)
	p := &Plugin{
		jwtValidator:     jwtValidator,
		serviceClientIDs: map[string]struct{}{"dashboard-service": {}},
	}

	_, err = p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
		Token:          mintServiceToken(t, key, "dashboard-service@clients", "pat:issue"),
		RequiredScopes: []string{"pat:issue"},
	})
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error, got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}

func TestValidateServiceToken_ScopeMatching(t *testing.T) {
	p, key := newServiceTestPlugin(t)

	tests := []struct {
		name           string
		scope          string
		requiredScopes []string
		wantCode       codes.Code
	}{
		{
			// A route that names no capability authorizes nothing, otherwise
			// any allowlisted client would pass the scope check vacuously.
			name:           "empty required scopes are refused",
			scope:          "pat:issue",
			requiredScopes: nil,
			wantCode:       codes.InvalidArgument,
		},
		{
			name:           "irregular whitespace between scopes",
			scope:          "  pat:issue \t services:read\n",
			requiredScopes: []string{"pat:issue", "services:read"},
			wantCode:       codes.OK,
		},
		{
			name:           "one of multiple required scopes missing",
			scope:          "pat:issue",
			requiredScopes: []string{"pat:issue", "services:read"},
			wantCode:       codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
				Token:          mintServiceToken(t, key, "dashboard-service@clients", tt.scope),
				RequiredScopes: tt.requiredScopes,
			})
			if tt.wantCode != codes.OK {
				st, ok := status.FromError(err)
				require.True(t, ok, "expected gRPC status error, got %v", err)
				require.Equal(t, tt.wantCode, st.Code())
				return
			}

			require.NoError(t, err)
			require.True(t, resp.Ok)
			require.Equal(t, "dashboard-service", resp.ClientId)
		})
	}
}

func TestValidateServiceToken_RejectsEmptyClientIDAndWrongGrantType(t *testing.T) {
	p, key := newServiceTestPlugin(t)

	tests := []struct {
		name  string
		token string
	}{
		{
			// sub exactly "@clients" strips to an empty client id.
			name:  "sub is exactly @clients",
			token: mintServiceToken(t, key, "@clients", "pat:issue"),
		},
		{
			name:  "wrong grant type",
			token: mintServiceTokenWithGrantType(t, key, "password"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
				Token:          tt.token,
				RequiredScopes: []string{"pat:issue"},
			})
			st, ok := status.FromError(err)
			require.True(t, ok, "expected gRPC status error, got %v", err)
			require.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// The allowlist parsed from a whitespace-padded env value authorizes every
// listed client end to end.
func TestValidateServiceToken_AllowlistBuiltFromWhitespaceConfig(t *testing.T) {
	p, key := newServiceTestPlugin(t)
	cfg := authConfig{ServiceClientIDs: " a , b "}
	p.serviceClientIDs = cfg.serviceClientIDSet()

	for _, clientID := range []string{"a", "b"} {
		resp, err := p.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
			Token:          mintServiceToken(t, key, clientID+"@clients", "pat:issue"),
			RequiredScopes: []string{"pat:issue"},
		})
		require.NoError(t, err)
		require.True(t, resp.Ok)
		require.Equal(t, clientID, resp.ClientId)
	}
}

func TestServiceClientIDSetEmptyConfigAuthorizesNothing(t *testing.T) {
	for _, raw := range []string{"", " , ,"} {
		cfg := authConfig{ServiceClientIDs: raw}
		require.Empty(t, cfg.serviceClientIDSet(), "raw config %q", raw)
	}
}

func TestServiceClientIDSetTrimsAndDeduplicatesClientIDs(t *testing.T) {
	cfg := authConfig{
		ServiceClientIDs: " dashboard-service,another-service, dashboard-service , ",
	}

	clientIDs := cfg.serviceClientIDSet()

	require.Len(t, clientIDs, 2)
	_, hasDashboard := clientIDs["dashboard-service"]
	_, hasAnother := clientIDs["another-service"]
	require.True(t, hasDashboard)
	require.True(t, hasAnother)
}

func requireUnauthenticated(t *testing.T, err error) *status.Status {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error, got %v", err)
	require.Equal(t, codes.Unauthenticated, st.Code(), "got: %v", st.Message())
	return st
}

func TestValidateToken_PATHappyPath(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	token := mintES256(t, key, "kid-1", patClaims())

	resp, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, "acct-1", resp.ClientId)
	require.Equal(t, "pat-jti-1", resp.Jti)
	require.Equal(t, "tenant-1", resp.KmsTenant)

	// Absent kms_tenant claim (pre-D9-backfill PATs) → empty string.
	claims := patClaims()
	delete(claims, "kms_tenant")
	resp, err = p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, key, "kid-1", claims),
	})
	require.NoError(t, err)
	require.Empty(t, resp.KmsTenant)
}

func TestValidateToken_WrongIssRejected(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	claims := patClaims()
	claims["iss"] = "https://somewhere-else.test"
	token := mintES256(t, key, "kid-1", claims)

	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	requireUnauthenticated(t, err)
	require.Equal(t, 0, mock.callCount())
}

func TestValidateToken_Auth0CustomerTokenRejected(t *testing.T) {
	svc, key := newServiceTestPlugin(t)
	p := newTestPlugin(t, startMockIssuer(t, &mockIssuer{}))
	p.jwtValidator = svc.jwtValidator

	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintServiceToken(t, key, "some-customer@clients", ""),
	})
	requireUnauthenticated(t, err)
}

func TestValidateToken_UnknownKidRefetches(t *testing.T) {
	oldKey := newP256Key(t)
	newKey := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-old", &oldKey.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	// Prime the cache with the old key.
	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, oldKey, "kid-old", patClaims()),
	})
	require.NoError(t, err)
	require.Equal(t, 1, mock.callCount())

	// The throttle is disabled here so rotation pickup is tested on its own;
	// TestValidateToken_UnknownKidRefetchIsThrottled covers the throttle.
	p.patKeys.minRefresh = 0
	mock.setJWKS(jwksJSON("kid-new", &newKey.PublicKey))
	resp, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, newKey, "kid-new", patClaims()),
	})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, 2, mock.callCount())
}

func TestValidateToken_ExpiredPATRejected(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	claims := patClaims()
	claims["iat"] = time.Now().Add(-time.Hour).Unix()
	claims["exp"] = time.Now().Add(-5 * time.Minute).Unix() // beyond the 1min leeway
	token := mintES256(t, key, "kid-1", claims)

	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	require.Error(t, err)
	// Both halves are load-bearing: the gateway matches either.
	st, ok := status.FromError(err)
	require.True(t, ok, "expired PAT must carry a gRPC status, got: %v", err)
	require.Equal(t, codes.Unauthenticated, st.Code())
	require.True(t, strings.Contains(st.Message(), "pat_expired:"), "got: %v", st.Message())
}

func TestValidateToken_AlgConfusionRejected(t *testing.T) {
	esKey := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &esKey.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	// RS256-signed token carrying the PAT iss routes to the PAT path and
	// must be rejected by WithValidMethods(["ES256"]).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, patClaims())
	token.Header["kid"] = "kid-1"
	signed, err := token.SignedString(rsaKey)
	require.NoError(t, err)

	_, err = p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: signed})
	requireUnauthenticated(t, err)
}

func TestValidateToken_MissingJtiRejected(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	claims := patClaims()
	delete(claims, "jti")
	token := mintES256(t, key, "kid-1", claims)

	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	st := requireUnauthenticated(t, err)
	require.Contains(t, st.Message(), "missing jti")
}

func TestNewPlugin_PartialPatConfigFailsStartup(t *testing.T) {
	viper.Reset()
	t.Setenv("ORBITPORT_AUTH0_DOMAIN", "auth0.invalid")
	t.Setenv("ORBITPORT_AUTH0_AUDIENCE", testPatAud)
	t.Setenv("ORBITPORT_AUTH_PAT_ISS", testPatIss)
	// ORBITPORT_AUTH_PATISSUER_PLUGIN deliberately unset — fail-closed.
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	_, err := NewPlugin()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ORBITPORT_AUTH_PATISSUER_PLUGIN")
}

// The keyfunc runs before signature verification, so without a throttle each
// bogus kid buys a JWKS refetch — unsigned garbage becomes issuer load.
func TestValidateToken_UnknownKidRefetchIsThrottled(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	// Prime the cache.
	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, key, "kid-1", patClaims()),
	})
	require.NoError(t, err)
	require.Equal(t, 1, mock.callCount())

	// A flood of unsigned tokens naming made-up kids must not reach the issuer.
	for i := 0; i < 25; i++ {
		_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
			Token: mintES256(t, key, fmt.Sprintf("bogus-kid-%d", i), patClaims()),
		})
		require.Error(t, err)
	}
	require.Equal(t, 1, mock.callCount(), "bogus kids must not trigger JWKS refetches")

	// A genuinely valid kid still verifies from cache throughout.
	resp, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, key, "kid-1", patClaims()),
	})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, 1, mock.callCount())
}

// An unreachable patissuer plugin is an outage, not a bad token: it must surface
// as Unavailable so the gateway answers 503 rather than 401.
func TestValidateToken_IssuerOutageIsUnavailable(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	addr := startMockIssuer(t, mock)
	p := newTestPlugin(t, addr)

	// Prime the cache, then age it past the TTL so the next call must refetch.
	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, key, "kid-1", patClaims()),
	})
	require.NoError(t, err)

	// Point the cache at a dead address to simulate the issuer going away.
	dead, err := newJWKSCache("127.0.0.1:1")
	require.NoError(t, err)
	p.patKeys = dead

	_, err = p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, key, "kid-1", patClaims()),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "issuer outage must carry a gRPC status, got: %v", err)
	require.Equal(t, codes.Unavailable, st.Code(), "got: %v", st.Message())
}

// A credential allowlisted for gateway-internal capabilities targets the same
// Auth0 audience as customer tokens, so ValidateToken must refuse it outright.
func TestValidateTokenRejectsServiceCredentials(t *testing.T) {
	plugin, key := newServiceTestPlugin(t)

	_, err := plugin.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintServiceToken(t, key, "dashboard-service@clients", "pat:issue"),
	})
	requireUnauthenticated(t, err)
}

// The two RPCs partition credentials: a client is either allowlisted for
// gateway-internal capabilities or a customer on the metered API, never both.
// Each half is asserted elsewhere; this pins the invariant that spans them.
func TestServiceAndCustomerCredentialsArePartitioned(t *testing.T) {
	plugin, key := newServiceTestPlugin(t)

	service := mintServiceToken(t, key, "dashboard-service@clients", "pat:issue")
	customer := mintServiceToken(t, key, "some-customer@clients", "pat:issue")

	serviceResp, err := plugin.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
		Token:          service,
		RequiredScopes: []string{"pat:issue"},
	})
	require.NoError(t, err)
	require.Equal(t, "dashboard-service", serviceResp.ClientId)

	_, err = plugin.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: service})
	requireUnauthenticated(t, err)

	_, err = plugin.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: customer})
	requireUnauthenticated(t, err)

	_, err = plugin.ValidateServiceToken(context.Background(), &proto.ServiceTokenValidationRequest{
		Token:          customer,
		RequiredScopes: []string{"pat:issue"},
	})
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error, got %v", err)
	require.Equal(t, codes.PermissionDenied, st.Code())
}

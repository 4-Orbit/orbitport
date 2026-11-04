package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const (
	jwksCacheTTL = 5 * time.Minute
	// Throttles the unknown-kid refetch: the keyfunc runs before signature
	// verification, so bogus kids would otherwise buy an RPC per request.
	// Tradeoff: a rotated key can 401 for up to this long.
	jwksMinRefresh   = 10 * time.Second
	jwksFetchTimeout = 5 * time.Second
)

// errIssuerUnavailable separates "we could not reach the issuer" (a 503)
// from "this token is bad" (a 401).
var errIssuerUnavailable = errors.New("patissuer plugin unavailable")

// unverifiedIssuer decodes the JWT payload WITHOUT verification, solely to
// read the iss claim for routing between the PAT and Auth0 paths. The token
// is fully verified afterwards by whichever path it routes to.
func unverifiedIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Iss
}

// jwksCache caches the patissuer plugin's JWKS as a kid -> public key map for
// jwksCacheTTL, refetching once on an unknown kid to pick up key rotation.
type jwksCache struct {
	client proto.PatIssuerPluginClient

	// mu guards the cached data only — never held across the network call.
	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time

	// refreshMu collapses concurrent refreshes into a single RPC.
	refreshMu sync.Mutex

	// A field so tests can drive the throttle.
	minRefresh time.Duration
}

func (c *jwksCache) snapshot() (map[string]*ecdsa.PublicKey, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys, c.fetchedAt
}

func newJWKSCache(issuerPluginURL string) (*jwksCache, error) {
	conn, err := grpc.NewClient(
		issuerPluginURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to patissuer plugin: %w", err)
	}
	return &jwksCache{
		client:     proto.NewPatIssuerPluginClient(conn),
		minRefresh: jwksMinRefresh,
	}, nil
}

// key returns the ES256 public key for kid, refreshing the cache when stale
// or when the kid is unknown.
func (c *jwksCache) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	keys, fetchedAt := c.snapshot()

	if keys == nil || time.Since(fetchedAt) > jwksCacheTTL {
		if err := c.refresh(ctx); err != nil {
			return nil, err
		}
		keys, fetchedAt = c.snapshot()
	}
	if k, ok := keys[kid]; ok {
		return k, nil
	}

	if time.Since(fetchedAt) < c.minRefresh {
		return nil, fmt.Errorf("no JWKS key for kid %q", kid)
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	keys, _ = c.snapshot()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

// refresh fetches the JWKS with the RPC OUTSIDE the data lock, so a hung
// patissuer plugin never blocks readers holding valid cached keys.
func (c *jwksCache) refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	// Another goroutine may have refreshed while we waited for the lock.
	if keys, fetchedAt := c.snapshot(); keys != nil && time.Since(fetchedAt) < c.minRefresh {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()

	resp, err := c.client.GetJwks(ctx, &proto.GetJwksRequest{})
	if err != nil {
		return fmt.Errorf("%w: fetching JWKS from patissuer plugin: %v", errIssuerUnavailable, err)
	}
	keys, err := parseJWKS(resp.GetJwksJson())
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// parseJWKS extracts the EC P-256 signing keys from an RFC 7517 JWK Set.
func parseJWKS(jwksJSON string) (map[string]*ecdsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksJSON), &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS JSON: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("JWK kid %q: decoding x: %w", k.Kid, err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("JWK kid %q: decoding y: %w", k.Kid, err)
		}
		// uncompressed SEC 1 point: 0x04 || X || Y
		point := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, fmt.Errorf("JWK kid %q: invalid P-256 point: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable EC P-256 keys")
	}
	return keys, nil
}

// validatePAT verifies a PAT against the patissuer plugin's JWKS.
func (p *Plugin) validatePAT(ctx context.Context, tokenString string) (*proto.TokenValidationResponse, error) {
	keyfunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("PAT is missing kid header")
		}
		return p.patKeys.key(ctx, kid)
	}

	parsed, err := jwt.Parse(
		tokenString,
		keyfunc,
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(p.patIss),
		jwt.WithAudience(p.patAudience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(time.Minute),
	)
	if err != nil {
		// A JWKS fetch failure is an outage, not a bad token: 503, not 401.
		if errors.Is(err, errIssuerUnavailable) {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			// The "pat_expired:" prefix is kept so an older gateway still
			// matches on the string.
			return nil, status.Error(codes.Unauthenticated, "pat_expired: "+err.Error())
		}
		return nil, status.Errorf(codes.Unauthenticated, "invalid_credential: %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "invalid_credential: unexpected PAT claims type %T", parsed.Claims)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, status.Errorf(codes.Unauthenticated, "invalid_credential: validated PAT is missing sub claim")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, status.Errorf(codes.Unauthenticated, "invalid_credential: validated PAT is missing jti claim")
	}
	// Optional until the D9 backfill lands — empty means no frozen tenant.
	kmsTenant, _ := claims["kms_tenant"].(string)

	return &proto.TokenValidationResponse{
		Ok:        true,
		ClientId:  sub,
		Jti:       jti,
		KmsTenant: kmsTenant,
	}, nil
}

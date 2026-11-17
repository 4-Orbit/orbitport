package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestValidateToken_AgentIDClaimIsReturned(t *testing.T) {
	key := newP256Key(t)
	p := newTestPlugin(t, startMockIssuer(t, &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}))

	claims := patClaims()
	claims["agent_id"] = "developer-agent"
	resp, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: mintES256(t, key, "kid-1", claims)})
	require.NoError(t, err)
	require.Equal(t, "developer-agent", resp.AgentId)

	// Account-level PAT: no claim, no agent.
	resp, err = p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: mintES256(t, key, "kid-1", patClaims())})
	require.NoError(t, err)
	require.Empty(t, resp.AgentId)
}

func TestValidateToken_MalformedAgentIDRejectsToken(t *testing.T) {
	key := newP256Key(t)
	p := newTestPlugin(t, startMockIssuer(t, &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}))
	for _, bad := range []any{"", "Developer Agent", "../x", 42, []string{"a"}} {
		claims := patClaims()
		claims["agent_id"] = bad
		_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: mintES256(t, key, "kid-1", claims)})
		requireUnauthenticated(t, err)
	}
}

func TestValidateToken_AgentIDCannotBeForged(t *testing.T) {
	signer := newP256Key(t)
	attacker := newP256Key(t)
	p := newTestPlugin(t, startMockIssuer(t, &mockIssuer{jwks: jwksJSON("kid-1", &signer.PublicKey)}))
	claims := patClaims()
	claims["agent_id"] = "security-agent"
	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: mintES256(t, attacker, "kid-1", claims)})
	requireUnauthenticated(t, err)
}

package patissuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

func TestIssueToken_AgentID_StampsClaim(t *testing.T) {
	p := newTestPlugin(t, nil)
	resp, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti: "jti-agent", Subject: "acct-1", AgentId: "developer-agent",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	require.Equal(t, "developer-agent", claimsOf(t, resp.Token)["agent_id"])
}

func TestIssueToken_NoAgentID_OmitsClaim(t *testing.T) {
	p := newTestPlugin(t, nil)
	_, present := claimsOf(t, issueValid(t, p))["agent_id"]
	require.False(t, present)
}

func TestIssueToken_AgentID_RejectsMalformedAndOutOfRangeLifetimes(t *testing.T) {
	p := newTestPlugin(t, nil)
	cases := []struct {
		name  string
		agent string
		ttl   time.Duration
	}{
		{"uppercase id", "Developer", time.Hour},
		{"path id", "../admin", time.Hour},
		{"too short", "developer-agent", 10 * time.Second},
		{"too long", "developer-agent", 48 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
				Jti: "j", Subject: "acct-1", AgentId: tc.agent, ExpiresAt: time.Now().Add(tc.ttl).Unix(),
			})
			require.Error(t, err)
		})
	}
}

// The gateway computes expires_at as whole-second now + ttl, so a token at
// exactly the minimum lifetime measures a fraction of a second short.
func TestIssueToken_AgentMinimumLifetimeAllowsWholeSecondRounding(t *testing.T) {
	p := newTestPlugin(t, nil)
	min := int64(p.cfg.AgentMinTTLSecs)
	_, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti: "j", Subject: "acct-1", AgentId: "developer-agent", ExpiresAt: time.Now().Unix() + min,
	})
	require.NoError(t, err, "a token at exactly the minimum lifetime is accepted")
	_, err = p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti: "j2", Subject: "acct-1", AgentId: "developer-agent", ExpiresAt: time.Now().Unix() + min - 2,
	})
	require.Error(t, err, "two seconds short is still too short")
}

func TestIssueToken_AgentTTLBoundsConfigurable(t *testing.T) {
	p := newTestPlugin(t, map[string]string{"ORBITPORT_PATISSUER_AGENT_MAX_TTL_SECS": "172800"})
	_, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti: "j", Subject: "acct-1", AgentId: "developer-agent", ExpiresAt: time.Now().Add(47 * time.Hour).Unix(),
	})
	require.NoError(t, err)
}

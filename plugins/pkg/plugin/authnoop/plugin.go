package authnoop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Plugin implements a development-only auth plugin that accepts all tokens.
type Plugin struct {
	proto.AuthPluginServer
}

// NewPlugin creates a noop auth plugin for local development environments.
func NewPlugin() (*Plugin, error) {
	utils.GetLogger("orbitport:authnoop").Warn(
		"Using noop auth plugin: all tokens will be accepted. Do not use in production!",
	)
	return new(Plugin), nil
}

// devAgentPrefix lets the noop stack exercise agent policies: a bearer token
// "agent:<agent_id>" is treated as that agent. It is no weaker than the rest
// of this plugin, which accepts every token, and it never exists in the real
// auth plugin, where agent_id comes only from a signed PAT claim.
const devAgentPrefix = "agent:"

var devAgentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidateToken handles the ValidateToken RPC call.
func (p *Plugin) ValidateToken(_ context.Context, req *proto.TokenValidationRequest) (*proto.TokenValidationResponse, error) {
	utils.GetLogger("orbitport:authnoop").Warn("Processing request with noop authentication")
	sum := sha256.Sum256([]byte(req.Token))
	agentID := ""
	if rest, ok := strings.CutPrefix(req.Token, devAgentPrefix); ok && devAgentRe.MatchString(rest) {
		agentID = rest
	}
	return &proto.TokenValidationResponse{
		Ok:       true,
		ClientId: "dev_" + hex.EncodeToString(sum[:8]),
		AgentId:  agentID,
	}, nil
}

// ValidateServiceToken accepts every token in development, mirroring
// ValidateToken. Production deployments must use the auth plugin.
func (p *Plugin) ValidateServiceToken(
	_ context.Context,
	req *proto.ServiceTokenValidationRequest,
) (*proto.ServiceTokenValidationResponse, error) {
	utils.GetLogger("orbitport:authnoop").Warn("Processing service token with noop authentication")
	sum := sha256.Sum256([]byte(req.Token))
	return &proto.ServiceTokenValidationResponse{
		Ok:       true,
		ClientId: "dev_" + hex.EncodeToString(sum[:8]),
	}, nil
}

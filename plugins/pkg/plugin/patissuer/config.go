package patissuer

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	signerLocal   = "local"
	signerTransit = "transit"
)

// patissuerConfig is the configuration for the patissuer plugin.
type patissuerConfig struct {
	Issuer   string
	Audience string
	Signer   string
	// Empty = generate an ephemeral key at startup, invalidating every
	// outstanding PAT on restart.
	LocalKeyPEM string
	MaxTTLDays  int
	// Agent PATs (agent_id set) are short-lived: their lifetime must fall
	// within [AgentMinTTLSecs, AgentMaxTTLSecs].
	AgentMinTTLSecs int
	AgentMaxTTLSecs int
	OpenBaoProxyURL string
	TransitMount    string
	TransitKey      string
	TimeoutSecs     int
}

func trimValue(value string) string {
	return strings.TrimSpace(value)
}

func readFromEnv() *patissuerConfig {
	setDefaults()

	return &patissuerConfig{
		Issuer:          trimValue(viper.GetString("PATISSUER_ISS")),
		Audience:        trimValue(viper.GetString("PATISSUER_AUD")),
		Signer:          trimValue(viper.GetString("PATISSUER_SIGNER")),
		LocalKeyPEM:     viper.GetString("PATISSUER_LOCAL_KEY_PEM"),
		MaxTTLDays:      viper.GetInt("PATISSUER_MAX_TTL_DAYS"),
		AgentMinTTLSecs: viper.GetInt("PATISSUER_MIN_TTL_SECS"),
		AgentMaxTTLSecs: viper.GetInt("PATISSUER_AGENT_MAX_TTL_SECS"),
		OpenBaoProxyURL: trimValue(viper.GetString("PATISSUER_OPENBAO_PROXY_URL")),
		TransitMount:    trimValue(viper.GetString("PATISSUER_TRANSIT_MOUNT")),
		TransitKey:      trimValue(viper.GetString("PATISSUER_TRANSIT_KEY")),
		TimeoutSecs:     viper.GetInt("PATISSUER_TIMEOUT_SECS"),
	}
}

func setDefaults() {
	viper.SetDefault("PATISSUER_ISS", "")
	viper.SetDefault("PATISSUER_AUD", "")
	viper.SetDefault("PATISSUER_SIGNER", signerLocal)
	viper.SetDefault("PATISSUER_LOCAL_KEY_PEM", "")
	viper.SetDefault("PATISSUER_MAX_TTL_DAYS", 370)
	viper.SetDefault("PATISSUER_MIN_TTL_SECS", 60)
	viper.SetDefault("PATISSUER_AGENT_MAX_TTL_SECS", 86400)
	viper.SetDefault("PATISSUER_OPENBAO_PROXY_URL", "")
	viper.SetDefault("PATISSUER_TRANSIT_MOUNT", "transit")
	viper.SetDefault("PATISSUER_TRANSIT_KEY", "pat-signing")
	viper.SetDefault("PATISSUER_TIMEOUT_SECS", 10)
}

// validate refuses startup when required vars are missing. Fail-closed.
func (c *patissuerConfig) validate() error {
	missing := []string{}
	if c.Issuer == "" {
		missing = append(missing, "ORBITPORT_PATISSUER_ISS")
	}
	if c.Audience == "" {
		missing = append(missing, "ORBITPORT_PATISSUER_AUD")
	}
	if len(missing) > 0 {
		return fmt.Errorf("FATAL: patissuer plugin missing required env vars: %s", strings.Join(missing, ", "))
	}
	if c.Signer != signerLocal && c.Signer != signerTransit {
		return fmt.Errorf("ORBITPORT_PATISSUER_SIGNER must be %q or %q, got %q", signerLocal, signerTransit, c.Signer)
	}
	if c.Signer == signerTransit {
		if c.OpenBaoProxyURL == "" {
			return fmt.Errorf("FATAL: ORBITPORT_PATISSUER_OPENBAO_PROXY_URL is required when ORBITPORT_PATISSUER_SIGNER=transit")
		}
		if c.TransitMount == "" || c.TransitKey == "" {
			return fmt.Errorf("ORBITPORT_PATISSUER_TRANSIT_MOUNT and ORBITPORT_PATISSUER_TRANSIT_KEY must be non-empty")
		}
		if c.TimeoutSecs <= 0 {
			return fmt.Errorf("ORBITPORT_PATISSUER_TIMEOUT_SECS must be > 0")
		}
	}
	if c.MaxTTLDays <= 0 {
		return fmt.Errorf("ORBITPORT_PATISSUER_MAX_TTL_DAYS must be > 0")
	}
	return nil
}

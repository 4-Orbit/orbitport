// Command fourorbit-seed prepares a local 4Orbit + Orbitport stack:
//
//  1. mints an operator (account-level) PAT straight from plugin-patissuer;
//  2. creates the demo Transit keys demo-key, dev-key and prod-key;
//  3. loads the 4Orbit policy template and its test suite, then activates it
//     (only if the tenant has no active policy, unless FOURORBIT_RESEED=true);
//  4. mints one short-lived agent PAT per registered agent.
//
// Tokens are written to $FOURORBIT_OUT_DIR/tokens/<name>.pat with mode 0600.
// It runs inside the compose network (the patissuer port is not published)
// and is idempotent: re-running only refreshes tokens.
//
// Development only: the patissuer mint RPC is unauthenticated by design and
// must never be reachable outside the cluster.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(env(key, "")); err == nil {
		return v
	}
	return def
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fourorbit-seed: "+err.Error())
		os.Exit(1)
	}
}

type gateway struct {
	url   string
	token string
	id    int
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (g *gateway) call(method string, params any, into any) error {
	g.id++
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": g.id, "method": method, "params": params})
	req, _ := http.NewRequest(http.MethodPost, g.url+"/api/v1/rpc", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d: %s", method, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: %s", method, envelope.Error.Message)
	}
	if into != nil {
		return json.Unmarshal(envelope.Result, into)
	}
	return nil
}

func waitHealthy(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("gateway at %s not healthy after %s", url, timeout)
		}
		time.Sleep(2 * time.Second)
	}
}

func randomID(prefix string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

func writeToken(dir, name, token string) error {
	path := filepath.Join(dir, name+".pat")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

var demoKeys = []struct{ alias, env string }{
	{"demo-key", "demo"},
	{"dev-key", "dev"},
	{"prod-key", "prod"},
}

func run() error {
	gatewayURL := env("FOURORBIT_GATEWAY_URL", "http://gateway:8080")
	issuerAddr := env("FOURORBIT_PATISSUER_ADDR", "plugin-patissuer:50006")
	outDir := env("FOURORBIT_OUT_DIR", "/out")
	operatorTTL := envInt("FOURORBIT_OPERATOR_TOKEN_TTL", 43200)
	agentTTL := envInt("FOURORBIT_AGENT_TOKEN_TTL", 3600)
	reseed := env("FOURORBIT_RESEED", "false") == "true"

	tokenDir := filepath.Join(outDir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", tokenDir, err)
	}

	fmt.Printf("waiting for gateway %s\n", gatewayURL)
	if err := waitHealthy(gatewayURL, 3*time.Minute); err != nil {
		return err
	}

	conn, err := grpc.NewClient(issuerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	issuer := proto.NewPatIssuerPluginClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	minted, err := issuer.IssueToken(ctx, &proto.IssueTokenRequest{
		Jti:       randomID("operator-"),
		Subject:   env("FOURORBIT_OPERATOR_SUBJECT", "fourorbit-operator"),
		ExpiresAt: time.Now().Add(time.Duration(operatorTTL) * time.Second).Unix(),
	})
	if err != nil {
		return fmt.Errorf("mint operator PAT: %w", err)
	}
	if err := writeToken(tokenDir, "operator", minted.Token); err != nil {
		return err
	}
	fmt.Printf("operator token -> %s/operator.pat (ttl %ds)\n", tokenDir, operatorTTL)

	gw := &gateway{url: gatewayURL, token: minted.Token}

	for _, k := range demoKeys {
		if err := gw.call("kms.GetKeyMetadata", map[string]any{"KeyId": "kms:" + k.alias}, nil); err == nil {
			fmt.Printf("key %s exists\n", k.alias)
			continue
		}
		err := gw.call("kms.CreateKey", map[string]any{
			"Description": "4Orbit demo key (" + k.env + ")",
			"Scheme":      "TRANSIT",
			"KeySpec":     "AES_256_GCM96",
			"KeyUsage":    "ENCRYPT_DECRYPT",
			"Alias":       k.alias,
			"Tags":        []map[string]string{{"TagKey": "env", "TagValue": k.env}},
		}, nil)
		if err != nil {
			return fmt.Errorf("create %s: %w", k.alias, err)
		}
		fmt.Printf("key %s created (env=%s)\n", k.alias, k.env)
	}

	var active struct {
		Exists  bool `json:"exists"`
		Version struct {
			Version  int64           `json:"version"`
			Entities json.RawMessage `json:"entities"`
		} `json:"version"`
	}
	if err := gw.call("policy.GetActive", map[string]any{}, &active); err != nil {
		return err
	}
	if !active.Exists || reseed {
		var loaded struct {
			Version int64 `json:"version"`
			Tests   int   `json:"tests"`
		}
		if err := gw.call("policy.LoadTemplate", map[string]any{"template": "4orbit"}, &loaded); err != nil {
			return err
		}
		var activated struct {
			Activated bool `json:"activated"`
			Tests     struct {
				Passed int `json:"passed"`
				Failed int `json:"failed"`
			} `json:"tests"`
		}
		if err := gw.call("policy.Activate", map[string]any{"version": loaded.Version}, &activated); err != nil {
			return err
		}
		if !activated.Activated {
			return fmt.Errorf("template v%d did not activate: %d test(s) failed", loaded.Version, activated.Tests.Failed)
		}
		fmt.Printf("policy v%d activated (%d/%d tests passed)\n", loaded.Version, activated.Tests.Passed, loaded.Tests)
		// The KMS plugin may have cached "no tenant policy" from the key calls
		// above; wait out its cache so "seed complete" means agents are live.
		wait := time.Duration(envInt("FOURORBIT_POLICY_CACHE_TTL_SECS", 5)+1) * time.Second
		fmt.Printf("waiting %s for the KMS policy cache\n", wait)
		time.Sleep(wait)
		if err := gw.call("policy.GetActive", map[string]any{}, &active); err != nil {
			return err
		}
	} else {
		fmt.Printf("policy v%d already active (set FOURORBIT_RESEED=true to reload the template)\n", active.Version.Version)
	}

	var entities []struct {
		UID struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"uid"`
	}
	_ = json.Unmarshal(active.Version.Entities, &entities)
	for _, e := range entities {
		if e.UID.Type != "Agent" {
			continue
		}
		var issued struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expiresAt"`
		}
		if err := gw.call("policy.IssueAgentToken", map[string]any{"agentId": e.UID.ID, "ttlSeconds": agentTTL}, &issued); err != nil {
			return err
		}
		if err := writeToken(tokenDir, e.UID.ID, issued.Token); err != nil {
			return err
		}
		fmt.Printf("agent token %s -> %s/%s.pat (expires %s)\n", e.UID.ID, tokenDir, e.UID.ID, time.Unix(issued.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	fmt.Println("seed complete")
	return nil
}

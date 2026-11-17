package kms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
)

type openBaoClient struct {
	*openbao.Client
	baseURL       string
	ethereumMount string
	keyStoreMount string
	kvMount       string
	pqcMount      string
	transitMount  string
}

type keyMetadataRecord struct {
	KeyID          string       `json:"key_id"`
	ClientID       string       `json:"client_id"`
	Alias          string       `json:"alias,omitempty"`
	Scheme         string       `json:"scheme"`
	ProviderKey    string       `json:"provider_key,omitempty"`
	TransitKey     string       `json:"transit_key,omitempty"`
	Description    string       `json:"description"`
	KeySpec        string       `json:"key_spec"`
	KeyUsage       string       `json:"key_usage"`
	Enabled        bool         `json:"enabled"`
	PrimaryVersion uint32       `json:"primary_version"`
	CreatedAt      string       `json:"created_at"`
	PublicKey      string       `json:"public_key,omitempty"`
	Address        string       `json:"address,omitempty"`
	Tags           []*pluginTag `json:"tags"`
}

type pluginTag struct {
	TagKey   string `json:"tag_key"`
	TagValue string `json:"tag_value"`
}

type transitKeyInfo struct {
	LatestVersion uint32                     `json:"latest_version"`
	Type          string                     `json:"type"`
	PublicKey     string                     `json:"public_key"`
	Keys          map[string]json.RawMessage `json:"keys"`
}

type transitKeyVersionInfo struct {
	PublicKey string `json:"public_key"`
}

type ethereumKeyInfo struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

type ethereumSignInfo struct {
	Signature string `json:"signature"`
	Hash      string `json:"hash"`
	Method    string `json:"method"`
	Address   string `json:"address"`
}

type pqcKeyInfo struct {
	Name      string `json:"name"`
	Version   uint32 `json:"version"`
	Variant   string `json:"variant"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

type pqcSignInfo struct {
	Name      string `json:"name"`
	Variant   string `json:"variant"`
	Signature string `json:"signature"`
}

type pqcDecapsulateInfo struct {
	Name      string `json:"name"`
	Variant   string `json:"variant"`
	SharedKey string `json:"shared_key"`
}

func newOpenBaoClient(cfg *kmsConfig) *openBaoClient {
	cfg = withKMSConfigDefaults(cfg)
	logger.Infof(
		"initializing OpenBao client with base_url=%s transit_mount=%s kv_mount=%s key_store_mount=%s ethereum_mount=%s pqc_mount=%s timeout_secs=%d",
		strings.TrimRight(cfg.OpenBaoProxyURL, "/"),
		cfg.TransitMount,
		cfg.KVMount,
		cfg.KeyStoreMount,
		cfg.EthereumMount,
		cfg.PQCMount,
		cfg.TimeoutSecs,
	)
	return &openBaoClient{
		Client: openbao.NewClient(&http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		}, logger),
		baseURL:       strings.TrimRight(cfg.OpenBaoProxyURL, "/"),
		ethereumMount: cfg.EthereumMount,
		keyStoreMount: cfg.KeyStoreMount,
		kvMount:       cfg.KVMount,
		pqcMount:      cfg.PQCMount,
		transitMount:  cfg.TransitMount,
	}
}

func (m *keyMetadataRecord) normalize() {
	if m.Scheme == "" {
		m.Scheme = schemeTransit
	}
	if m.ProviderKey == "" {
		m.ProviderKey = m.TransitKey
	}
}

func (m *keyMetadataRecord) backendKey() string {
	if m.ProviderKey != "" {
		return m.ProviderKey
	}
	return m.TransitKey
}

func (t *transitKeyInfo) exportedPublicKey() string {
	if t.PublicKey != "" {
		return t.PublicKey
	}
	if len(t.Keys) == 0 {
		return ""
	}

	if t.LatestVersion != 0 {
		if publicKey := transitVersionPublicKey(t.Keys[strconv.FormatUint(uint64(t.LatestVersion), 10)]); publicKey != "" {
			return publicKey
		}
	}

	latestVersion := -1
	var latestPublicKey string
	for version, raw := range t.Keys {
		publicKey := transitVersionPublicKey(raw)
		if publicKey == "" {
			continue
		}
		versionNum, err := strconv.Atoi(version)
		if err != nil {
			continue
		}
		if versionNum > latestVersion {
			latestVersion = versionNum
			latestPublicKey = publicKey
		}
	}
	return latestPublicKey
}

func (t *transitKeyInfo) publicKeyForVersion(version uint32) string {
	if version == 0 {
		return ""
	}
	if version == t.LatestVersion && t.PublicKey != "" {
		return t.PublicKey
	}
	if len(t.Keys) == 0 {
		return ""
	}
	return transitVersionPublicKey(t.Keys[strconv.FormatUint(uint64(version), 10)])
}

func transitVersionPublicKey(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var version transitKeyVersionInfo
	if err := json.Unmarshal(raw, &version); err != nil {
		return ""
	}
	return version.PublicKey
}

func (c *openBaoClient) createTransitKey(ctx context.Context, name, keyType string) (*transitKeyInfo, error) {
	if err := c.Post(ctx, c.transitPath("keys", name), map[string]any{"type": keyType}, nil); err != nil {
		return nil, err
	}
	return c.readTransitKey(ctx, name)
}

func (c *openBaoClient) readTransitKey(ctx context.Context, name string) (*transitKeyInfo, error) {
	var resp struct {
		Data transitKeyInfo `json:"data"`
	}
	if err := c.Get(ctx, c.transitPath("keys", name), &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) encrypt(ctx context.Context, transitKey, plaintext string) (string, error) {
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := c.Post(ctx, c.transitPath("encrypt", transitKey), map[string]any{
		"plaintext": plaintext,
	}, &resp)
	if err != nil {
		return "", err
	}
	return resp.Data.Ciphertext, nil
}

func (c *openBaoClient) decrypt(ctx context.Context, transitKey, ciphertext string) (string, error) {
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := c.Post(ctx, c.transitPath("decrypt", transitKey), map[string]any{
		"ciphertext": ciphertext,
	}, &resp)
	if err != nil {
		return "", err
	}
	return resp.Data.Plaintext, nil
}

func (c *openBaoClient) sign(ctx context.Context, transitKey, message string, mapping *signMapping, keyVersion uint32) (string, error) {
	body := map[string]any{
		"input":     message,
		"prehashed": mapping.prehashed,
	}
	if mapping.signatureAlgorithm != "" {
		body["signature_algorithm"] = mapping.signatureAlgorithm
	}
	if keyVersion != 0 {
		body["key_version"] = keyVersion
	}

	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	err := c.Post(ctx, c.transitPath("sign", transitKey, mapping.pathAlgorithm), body, &resp)
	if err != nil {
		return "", err
	}
	return resp.Data.Signature, nil
}

func (c *openBaoClient) generateDataKey(ctx context.Context, transitKey string, bits int) (string, string, error) {
	var resp struct {
		Data struct {
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := c.Post(ctx, c.transitPath("datakey", "plaintext", transitKey), map[string]any{
		"bits": bits,
	}, &resp)
	if err != nil {
		return "", "", err
	}
	return resp.Data.Plaintext, resp.Data.Ciphertext, nil
}

func (c *openBaoClient) rotateTransitKey(ctx context.Context, transitKey string) (*transitKeyInfo, error) {
	if err := c.Post(ctx, c.transitPath("keys", transitKey, "rotate"), map[string]any{}, nil); err != nil {
		return nil, err
	}
	return c.readTransitKey(ctx, transitKey)
}

func (c *openBaoClient) createEthereumKey(ctx context.Context, name string) (*ethereumKeyInfo, error) {
	var resp struct {
		Data ethereumKeyInfo `json:"data"`
	}
	if err := c.Post(ctx, c.ethereumPath("keys", name), map[string]any{}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) signEthereumHash(ctx context.Context, keyName, hash string) (*ethereumSignInfo, error) {
	return c.signEthereum(ctx, keyName, map[string]any{"hash": hash})
}

func (c *openBaoClient) signEthereumMessage(ctx context.Context, keyName, message string) (*ethereumSignInfo, error) {
	return c.signEthereum(ctx, keyName, map[string]any{"message": message})
}

func (c *openBaoClient) signEthereum(ctx context.Context, keyName string, body map[string]any) (*ethereumSignInfo, error) {
	var resp struct {
		Data ethereumSignInfo `json:"data"`
	}
	if err := c.Post(ctx, c.ethereumPath("sign", keyName), body, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) createPQCKey(ctx context.Context, name, variant string) (*pqcKeyInfo, error) {
	var resp struct {
		Data pqcKeyInfo `json:"data"`
	}
	if err := c.Post(ctx, c.pqcPath("mldsa", "keys", name), map[string]any{"variant": variant}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) createPQCKEMKey(ctx context.Context, name, variant string) (*pqcKeyInfo, error) {
	var resp struct {
		Data pqcKeyInfo `json:"data"`
	}
	if err := c.Post(ctx, c.pqcPath("mlkem", "keys", name), map[string]any{"variant": variant}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) signPQC(ctx context.Context, keyName, message string) (*pqcSignInfo, error) {
	var resp struct {
		Data pqcSignInfo `json:"data"`
	}
	if err := c.Post(ctx, c.pqcPath("mldsa", "sign", keyName), map[string]any{"message": message}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) decapsulatePQC(ctx context.Context, keyName, ciphertext string) (*pqcDecapsulateInfo, error) {
	var resp struct {
		Data pqcDecapsulateInfo `json:"data"`
	}
	if err := c.Post(ctx, c.pqcPath("mlkem", "decapsulate", keyName), map[string]any{"ciphertext": ciphertext}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) putMetadata(ctx context.Context, clientID, keyID string, metadata *keyMetadataRecord) error {
	return c.Post(ctx, c.metadataPath(clientID, keyID), map[string]any{
		"data": metadata,
	}, nil)
}

func (c *openBaoClient) getMetadata(ctx context.Context, clientID, keyID string) (*keyMetadataRecord, error) {
	var resp struct {
		Data struct {
			Data keyMetadataRecord `json:"data"`
		} `json:"data"`
	}
	if err := c.Get(ctx, c.metadataPath(clientID, keyID), &resp); err != nil {
		return nil, err
	}
	record := &resp.Data.Data
	record.normalize()
	if record.ClientID != "" && record.ClientID != clientID {
		return nil, fmt.Errorf("metadata owner does not match request owner")
	}
	return record, nil
}

// listMetadata returns the key IDs with stored metadata in the tenant's
// namespace. A tenant with no keys yields an empty list.
func (c *openBaoClient) listMetadata(ctx context.Context, clientID string) ([]string, error) {
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	target := c.joinPath("v1", c.kvMount, "metadata", "kms", "metadata", tenantNamespace(clientID))
	if err := c.List(ctx, target, &resp); err != nil {
		var statusErr *openbao.StatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, k := range resp.Data.Keys {
		if strings.HasSuffix(k, "/") {
			continue
		}
		if unescaped, err := url.PathUnescape(k); err == nil {
			k = unescaped
		}
		if strings.HasPrefix(k, keyIDPrefix) {
			ids = append(ids, k)
		}
	}
	return ids, nil
}

func (c *openBaoClient) metadataPath(clientID, keyID string) string {
	return c.kvPath("kms", "metadata", tenantNamespace(clientID), url.PathEscape(keyID))
}

func (c *openBaoClient) kvPath(parts ...string) string {
	all := append([]string{"v1", c.kvMount, "data"}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) transitPath(parts ...string) string {
	all := append([]string{"v1", c.transitMount}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) ethereumPath(parts ...string) string {
	all := append([]string{"v1", c.ethereumMount}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) pqcPath(parts ...string) string {
	all := append([]string{"v1", c.pqcMount}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) joinPath(parts ...string) string {
	u, _ := url.Parse(c.baseURL)
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		clean = append(clean, strings.Trim(part, "/"))
	}
	u.Path = path.Join(append([]string{u.Path}, clean...)...)
	return u.String()
}

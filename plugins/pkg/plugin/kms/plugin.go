package kms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	proto.UnimplementedKmsPluginServer

	client             *openBaoClient
	now                func() time.Time
	providers          map[string]kmsProvider
	keyStoreAuthorizer *keyStoreAuthorizer
	agentAuthz         *agentAuthorizer
}

var logger = utils.GetLogger("orbitport:kms")
var aliasCharsRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
var reservedKmsRe = regexp.MustCompile(`^kms:`)

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	cfg = withKMSConfigDefaults(cfg)
	if cfg.OpenBaoProxyURL == "" {
		return nil, fmt.Errorf("ORBITPORT_KMS_OPENBAO_PROXY_URL is required")
	}
	logger.Infof(
		"creating KMS plugin with proxy url=%s, transit mount=%s, kv mount=%s, key-store mount=%s, ethereum mount=%s, pqc mount=%s",
		cfg.OpenBaoProxyURL,
		cfg.TransitMount,
		cfg.KVMount,
		cfg.KeyStoreMount,
		cfg.EthereumMount,
		cfg.PQCMount,
	)
	return newPluginWithConfig(cfg, newOpenBaoClient(cfg))
}

func newPlugin(cfg *kmsConfig, client *openBaoClient) *Plugin {
	plugin, err := newPluginWithConfig(cfg, client)
	if err != nil {
		panic(err)
	}
	return plugin
}

func newPluginWithConfig(cfg *kmsConfig, client *openBaoClient) (*Plugin, error) {
	cfg = withKMSConfigDefaults(cfg)
	authorizer, err := newKeyStoreAuthorizer(cfg)
	if err != nil {
		return nil, err
	}
	agentAuthz, err := newAgentAuthorizer(cfg)
	if err != nil {
		return nil, err
	}
	return &Plugin{
		client:             client,
		now:                time.Now,
		keyStoreAuthorizer: authorizer,
		agentAuthz:         agentAuthz,
		providers: map[string]kmsProvider{
			schemeTransit:  newTransitProvider(client),
			schemeEthereum: newEthereumProvider(client),
			schemePQC:      newPQCProvider(client),
		},
	}, nil
}

func (p *Plugin) encryptImpl(ctx context.Context, req *proto.EncryptRequest) (*proto.EncryptResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("Encrypt request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Encrypt failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	encryptor, err := requireCipherProvider(provider, req.KeyId, metadata.Scheme, cipherOperationEncryption)
	if err != nil {
		return nil, err
	}
	resp, err := encryptor.Encrypt(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Encrypt failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Encrypt completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) decryptImpl(ctx context.Context, req *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	blob, err := decodeCiphertextBlob(req.CiphertextBlob)
	if err != nil {
		logger.Warn("Decrypt rejected invalid ciphertext blob")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	logger.Debugf("Decrypt request received for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
	if req.KeyId != nil {
		resolvedKeyID, err := p.resolveKeyID(*req.KeyId)
		if err != nil {
			logger.Warnf("Decrypt failed to resolve key reference for request key_id=%s", *req.KeyId)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if resolvedKeyID != blob.KeyID {
			logger.Warnf("Decrypt rejected mismatched key id: request=%s resolved=%s blob=%s", *req.KeyId, resolvedKeyID, blob.KeyID)
			return nil, status.Error(codes.InvalidArgument, "KeyId does not match CiphertextBlob")
		}
	}

	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, blob.KeyID)
	if err != nil {
		logger.Warnf("Decrypt failed to resolve metadata for key_id=%s", blob.KeyID)
		return nil, err
	}
	if metadata.KeyID != blob.KeyID || metadata.backendKey() != blob.backendKey() {
		logger.Warnf("Decrypt rejected mismatched ciphertext blob for key_id=%s", blob.KeyID)
		return nil, status.Error(codes.PermissionDenied, "CiphertextBlob does not belong to the authenticated client")
	}
	decryptor, err := requireCipherProvider(provider, blob.KeyID, metadata.Scheme, cipherOperationDecryption)
	if err != nil {
		return nil, err
	}
	resp, err := decryptor.Decrypt(ctx, blob, req)
	if err != nil {
		logger.Warnf("Decrypt failed for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
		return nil, err
	}
	logger.Debugf("Decrypt completed for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
	return resp, nil
}

func (p *Plugin) signImpl(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf(
		"Sign request received for key_id=%s signing_algorithm=%s message_type=%q",
		req.KeyId,
		req.SigningAlgorithm,
		optionalString(req.MessageType),
	)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Sign failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	signer, err := requireSignProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("Sign rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := signer.Sign(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Sign failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp.KeyVersion = metadata.PrimaryVersion
	logger.Debugf("Sign completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) encapsulateImpl(ctx context.Context, req *proto.EncapsulateRequest) (*proto.EncapsulateResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("Encapsulate request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Encapsulate failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	keyAgreement, err := requireKeyAgreementProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("Encapsulate rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := keyAgreement.Encapsulate(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Encapsulate failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Encapsulate completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) decapsulateImpl(ctx context.Context, req *proto.DecapsulateRequest) (*proto.DecapsulateResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("Decapsulate request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Decapsulate failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	keyAgreement, err := requireKeyAgreementProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("Decapsulate rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := keyAgreement.Decapsulate(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Decapsulate failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Decapsulate completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) createKeyImpl(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	scheme, err := normalizeScheme(optionalString(req.Scheme))
	if err != nil {
		logger.Warnf("CreateKey rejected unsupported scheme=%q", optionalString(req.Scheme))
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	logger.Infof(
		"CreateKey request received scheme=%s key_spec=%s key_usage=%s alias=%q tags=%d",
		scheme,
		req.KeySpec,
		req.KeyUsage,
		req.Alias,
		len(req.Tags),
	)

	alias := strings.TrimSpace(req.Alias)
	if err := validateAlias(alias); err != nil {
		logger.Warnf("CreateKey rejected invalid alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	keyID, err := canonicalKeyID(alias)
	if err != nil {
		logger.Warnf("CreateKey rejected alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := p.client.getMetadata(ctx, req.ClientId, keyID); err == nil {
		logger.Warnf("CreateKey rejected duplicate alias=%q", alias)
		return nil, status.Error(codes.AlreadyExists, "Alias already exists for this tenant")
	} else {
		var statusErr *openbao.StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
			logger.Warnf("CreateKey failed to verify key availability alias=%q", alias)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	provider, err := p.providerForScheme(scheme)
	if err != nil {
		logger.Warnf("CreateKey failed to resolve provider for scheme=%s", scheme)
		return nil, err
	}

	req.Alias = alias
	record, err := provider.CreateKey(ctx, req, keyID, p.now().UTC())
	if err != nil {
		logger.Warnf("CreateKey failed for key_id=%s scheme=%s", keyID, scheme)
		return nil, err
	}

	record.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, keyID, record); err != nil {
		logger.Warnf("CreateKey failed to persist metadata for key_id=%s scheme=%s", keyID, scheme)
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Infof("CreateKey completed key_id=%s scheme=%s", keyID, scheme)

	return &proto.CreateKeyResponse{
		KeyMetadata: toProtoMetadata(record),
	}, nil
}

func (p *Plugin) getKeyMetadataImpl(ctx context.Context, req *proto.GetKeyMetadataRequest) (*proto.GetKeyMetadataResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("GetKeyMetadata request received for key_id=%s", req.KeyId)
	metadata, _, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("GetKeyMetadata failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	logger.Debugf("GetKeyMetadata completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return &proto.GetKeyMetadataResponse{
		KeyMetadata: toProtoMetadata(metadata),
	}, nil
}

func (p *Plugin) getPublicKeyImpl(ctx context.Context, req *proto.GetPublicKeyRequest) (*proto.GetPublicKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	version := req.GetVersion()
	if req.Version != nil && version == 0 {
		return nil, status.Error(codes.InvalidArgument, "Version must be greater than 0")
	}
	logger.Debugf("GetPublicKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("GetPublicKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	publicKeyProvider, err := requirePublicKeyProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("GetPublicKey rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	publicKey, err := publicKeyProvider.GetPublicKey(ctx, metadata, version)
	if err != nil {
		logger.Warnf("GetPublicKey failed for key_id=%s scheme=%s version=%d", req.KeyId, metadata.Scheme, version)
		return nil, err
	}
	logger.Debugf("GetPublicKey completed for key_id=%s scheme=%s version=%d", req.KeyId, metadata.Scheme, publicKey.Version)
	return &proto.GetPublicKeyResponse{
		PublicKey: publicKey.PublicKey,
		Version:   publicKey.Version,
	}, nil
}

func (p *Plugin) generateDataKeyImpl(ctx context.Context, req *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("GenerateDataKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("GenerateDataKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	generator, err := requireDataKeyProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("GenerateDataKey rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := generator.GenerateDataKey(ctx, metadata, req)
	if err != nil {
		logger.Warnf("GenerateDataKey failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("GenerateDataKey completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) rotateKeyImpl(ctx context.Context, req *proto.RotateKeyRequest) (*proto.RotateKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Infof("RotateKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("RotateKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}

	rotator, err := requireRotateKeyProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("RotateKey rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	updated, err := rotator.RotateKey(ctx, metadata)
	if err != nil {
		logger.Warnf("RotateKey failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	updated.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, updated.KeyID, updated); err != nil {
		logger.Warnf("RotateKey failed to persist metadata for key_id=%s", updated.KeyID)
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Infof(
		"RotateKey completed for key_id=%s scheme=%s primary_version=%d",
		updated.KeyID,
		updated.Scheme,
		updated.PrimaryVersion,
	)

	return &proto.RotateKeyResponse{
		KeyMetadata: toProtoMetadata(updated),
	}, nil
}

func (p *Plugin) metadataProvider(ctx context.Context, clientID, keyID string) (*keyMetadataRecord, kmsProvider, error) {
	resolvedKeyID, err := p.resolveKeyID(keyID)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}

	metadata, err := p.client.getMetadata(ctx, clientID, resolvedKeyID)
	if err != nil {
		var statusErr *openbao.StatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
			logger.Warnf("denied access to key_id=%s for requesting client", resolvedKeyID)
			return nil, nil, status.Error(codes.PermissionDenied, "key does not belong to the authenticated client")
		}
		logger.Warnf("failed to fetch KMS metadata for key_id=%s", resolvedKeyID)
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	provider, err := p.providerForScheme(metadata.Scheme)
	if err != nil {
		logger.Warnf("failed to resolve provider for key_id=%s scheme=%s", resolvedKeyID, metadata.Scheme)
		return nil, nil, err
	}
	return metadata, provider, nil
}

func (p *Plugin) resolveKeyID(keyRef string) (string, error) {
	resolvedKeyID, _, err := resolveKeyRef(keyRef)
	return resolvedKeyID, err
}

func requireClientID(clientID string) error {
	if strings.TrimSpace(clientID) == "" {
		return status.Error(codes.InvalidArgument, "client_id is required")
	}
	return nil
}

func (p *Plugin) providerForScheme(scheme string) (kmsProvider, error) {
	normalized, err := normalizeScheme(scheme)
	if err != nil {
		logger.Warnf("unsupported KMS scheme=%q", scheme)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	provider, ok := p.providers[normalized]
	if !ok {
		logger.Warnf("no provider registered for KMS scheme=%q", normalized)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported Scheme %q", normalized))
	}
	return provider, nil
}

func toRecordTags(tags []*proto.Tag) []*pluginTag {
	result := make([]*pluginTag, 0, len(tags))
	for _, tag := range tags {
		result = append(result, &pluginTag{
			TagKey:   tag.TagKey,
			TagValue: tag.TagValue,
		})
	}
	return result
}

func toProtoTags(tags []*pluginTag) []*proto.Tag {
	result := make([]*proto.Tag, 0, len(tags))
	for _, tag := range tags {
		result = append(result, &proto.Tag{
			TagKey:   tag.TagKey,
			TagValue: tag.TagValue,
		})
	}
	return result
}

func toProtoMetadata(record *keyMetadataRecord) *proto.KeyMetadata {
	record.normalize()

	metadata := &proto.KeyMetadata{
		KeyId:          record.KeyID,
		Description:    record.Description,
		KeySpec:        record.KeySpec,
		KeyUsage:       record.KeyUsage,
		Enabled:        record.Enabled,
		PrimaryVersion: record.PrimaryVersion,
		CreationDate:   record.CreatedAt,
		Scheme:         record.Scheme,
		Tags:           toProtoTags(record.Tags),
	}
	if record.PublicKey != "" {
		metadata.PublicKey = &record.PublicKey
	}
	if record.Address != "" {
		metadata.Address = &record.Address
	}
	metadata.Alias = record.Alias
	return metadata
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func optionalUint32(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}

func validateAlias(alias string) error {
	const maxAliasLen = 128

	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	if len(alias) > maxAliasLen {
		return fmt.Errorf("alias must be at most %d characters", maxAliasLen)
	}
	if reservedKmsRe.MatchString(alias) {
		return fmt.Errorf("alias must not use the reserved kms:<alias> format")
	}
	if !aliasCharsRe.MatchString(alias) {
		return fmt.Errorf("alias contains unsupported characters")
	}
	return nil
}

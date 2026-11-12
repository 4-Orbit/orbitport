package kms

import (
	"context"
	"sort"
	"strings"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Every exported RPC goes through guard: the Cedar decision comes first and
// only an ALLOW reaches the handler (and therefore OpenBao). The handlers
// themselves live in the *Impl methods.

func (p *Plugin) Encrypt(ctx context.Context, req *proto.EncryptRequest) (*proto.EncryptResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.Encrypt", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.EncryptResponse, error) { return p.encryptImpl(ctx, req) })
}

func (p *Plugin) Decrypt(ctx context.Context, req *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	keyRef := optionalString(req.KeyId)
	if blob, err := decodeCiphertextBlob(req.CiphertextBlob); err == nil {
		keyRef = blob.KeyID
	}
	return guard(p, ctx, req.ClientId, "kms.Decrypt", p.keyResource(req.ClientId, keyRef),
		func() (*proto.DecryptResponse, error) { return p.decryptImpl(ctx, req) })
}

func (p *Plugin) Sign(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.Sign", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.SignResponse, error) { return p.signImpl(ctx, req) })
}

func (p *Plugin) Encapsulate(ctx context.Context, req *proto.EncapsulateRequest) (*proto.EncapsulateResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.Encapsulate", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.EncapsulateResponse, error) { return p.encapsulateImpl(ctx, req) })
}

func (p *Plugin) Decapsulate(ctx context.Context, req *proto.DecapsulateRequest) (*proto.DecapsulateResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.Decapsulate", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.DecapsulateResponse, error) { return p.decapsulateImpl(ctx, req) })
}

func (p *Plugin) GetKeyMetadata(ctx context.Context, req *proto.GetKeyMetadataRequest) (*proto.GetKeyMetadataResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.GetKeyMetadata", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.GetKeyMetadataResponse, error) { return p.getKeyMetadataImpl(ctx, req) })
}

func (p *Plugin) GetPublicKey(ctx context.Context, req *proto.GetPublicKeyRequest) (*proto.GetPublicKeyResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.GetPublicKey", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.GetPublicKeyResponse, error) { return p.getPublicKeyImpl(ctx, req) })
}

func (p *Plugin) GenerateDataKey(ctx context.Context, req *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.GenerateDataKey", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.GenerateDataKeyResponse, error) { return p.generateDataKeyImpl(ctx, req) })
}

func (p *Plugin) RotateKey(ctx context.Context, req *proto.RotateKeyRequest) (*proto.RotateKeyResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.RotateKey", p.keyResource(req.ClientId, req.KeyId),
		func() (*proto.RotateKeyResponse, error) { return p.rotateKeyImpl(ctx, req) })
}

// CreateKey has no stored key yet, so the resource is built from the request.
func (p *Plugin) CreateKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	scheme, _ := normalizeScheme(optionalString(req.Scheme))
	res := authz.Resource{
		Type:  "Key",
		ID:    strings.TrimSpace(req.Alias),
		Attrs: map[string]string{"scheme": scheme, "keySpec": req.KeySpec, "keyUsage": req.KeyUsage},
		Tags:  map[string]string{},
	}
	for _, t := range req.Tags {
		if t != nil && t.TagKey != "" {
			res.Tags[t.TagKey] = t.TagValue
		}
	}
	return guard(p, ctx, req.ClientId, "kms.CreateKey", staticResource(res),
		func() (*proto.CreateKeyResponse, error) { return p.createKeyImpl(ctx, req) })
}

func (p *Plugin) KeyStorePut(ctx context.Context, req *proto.KeyStorePutRequest) (*proto.KeyStorePutResponse, error) {
	return guard(p, ctx, req.ClientId, "kms_keystore.Put", keyStoreResource("KeyStoreKey", req.Name),
		func() (*proto.KeyStorePutResponse, error) { return p.keyStorePutImpl(ctx, req) })
}

func (p *Plugin) KeyStoreGet(ctx context.Context, req *proto.KeyStoreGetRequest) (*proto.KeyStoreGetResponse, error) {
	return guard(p, ctx, req.ClientId, "kms_keystore.Get", keyStoreResource("KeyStoreKey", req.Name),
		func() (*proto.KeyStoreGetResponse, error) { return p.keyStoreGetImpl(ctx, req) })
}

func (p *Plugin) KeyStoreDelete(ctx context.Context, req *proto.KeyStoreDeleteRequest) (*proto.KeyStoreDeleteResponse, error) {
	return guard(p, ctx, req.ClientId, "kms_keystore.Delete", keyStoreResource("KeyStoreKey", req.Name),
		func() (*proto.KeyStoreDeleteResponse, error) { return p.keyStoreDeleteImpl(ctx, req) })
}

func (p *Plugin) KeyStoreList(ctx context.Context, req *proto.KeyStoreListRequest) (*proto.KeyStoreListResponse, error) {
	prefix := strings.Trim(optionalString(req.Prefix), "/")
	if prefix == "" {
		prefix = "/"
	}
	return guard(p, ctx, req.ClientId, "kms_keystore.List", staticResource(authz.Resource{Type: "KeyStoreNamespace", ID: prefix}),
		func() (*proto.KeyStoreListResponse, error) { return p.keyStoreListImpl(ctx, req) })
}

func keyStoreResource(resourceType, name string) resourceResolver {
	n, err := normalizeKeyStoreName(name)
	if err != nil {
		n = "invalid"
	}
	return staticResource(authz.Resource{Type: resourceType, ID: n})
}

// maxListedKeys bounds one ListKeys response.
const maxListedKeys = 200

// ListKeys returns the tenant's key metadata for the policy playground.
func (p *Plugin) ListKeys(ctx context.Context, req *proto.ListKeysRequest) (*proto.ListKeysResponse, error) {
	return guard(p, ctx, req.ClientId, "kms.ListKeys", staticResource(authz.Resource{Type: "KeyNamespace", ID: "keys"}),
		func() (*proto.ListKeysResponse, error) { return p.listKeysImpl(ctx, req) })
}

func (p *Plugin) listKeysImpl(ctx context.Context, req *proto.ListKeysRequest) (*proto.ListKeysResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	ids, err := p.client.listMetadata(ctx, req.ClientId)
	if err != nil {
		return nil, keyStoreBackendStatus("list keys", err)
	}
	sort.Strings(ids)
	resp := &proto.ListKeysResponse{}
	for _, id := range ids {
		if len(resp.Keys) >= maxListedKeys {
			resp.Truncated = true
			break
		}
		md, err := p.client.getMetadata(ctx, req.ClientId, id)
		if err != nil {
			logger.Warnf("ListKeys skipped unreadable metadata key_id=%s", id)
			continue
		}
		resp.Keys = append(resp.Keys, toProtoMetadata(md))
	}
	return resp, nil
}

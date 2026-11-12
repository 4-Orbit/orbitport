package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxKeyStoreNameLen   = 256
	keyStoreActionPut    = "kms_keystore.Put"
	keyStoreActionGet    = "kms_keystore.Get"
	keyStoreActionList   = "kms_keystore.List"
	keyStoreActionDelete = "kms_keystore.Delete"
)

var (
	keyStoreSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func (p *Plugin) keyStorePutImpl(ctx context.Context, req *proto.KeyStorePutRequest) (*proto.KeyStorePutResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	secret, err := decodeKeyStoreSecretJSON(req.SecretJson)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionPut, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	version, err := p.client.putKeyStoreSecret(ctx, req.ClientId, name, secret, p.now().UTC())
	if err != nil {
		return nil, keyStoreBackendStatus("put", err)
	}
	logger.Debugf("key-store put completed name=%s owner=%s version=%d", name, tenantNamespace(req.ClientId), version)
	return &proto.KeyStorePutResponse{Name: name, Version: version}, nil
}

func (p *Plugin) keyStoreGetImpl(ctx context.Context, req *proto.KeyStoreGetRequest) (*proto.KeyStoreGetResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionGet, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	record, err := p.client.getKeyStoreSecret(ctx, req.ClientId, name)
	if err != nil {
		return nil, keyStoreNotFoundOrBackendStatus("get", err, "key-store entry not found")
	}
	if !isValidKeyStoreRecord(record, req.ClientId, name) {
		logger.Warnf("key-store get rejected invalid stored payload owner=%s name=%s", tenantNamespace(req.ClientId), name)
		return nil, status.Error(codes.PermissionDenied, "key-store entry does not belong to the requested key")
	}
	secretJSON, err := encodeKeyStoreSecretJSON(record)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Debugf("key-store get completed name=%s owner=%s", name, tenantNamespace(req.ClientId))
	return &proto.KeyStoreGetResponse{Name: name, SecretJson: secretJSON}, nil
}

func (p *Plugin) keyStoreListImpl(ctx context.Context, req *proto.KeyStoreListRequest) (*proto.KeyStoreListResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	prefix, err := normalizeKeyStorePrefix(optionalString(req.Prefix))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionList, keyStoreNamespaceType, "", prefix); err != nil {
		return nil, err
	}

	names, err := p.client.listKeyStoreSecrets(ctx, req.ClientId, prefix)
	if err != nil {
		if isOpenBaoStatus(err, http.StatusNotFound) {
			logKeyStoreOpenBaoError("list", err)
			return &proto.KeyStoreListResponse{Names: []string{}}, nil
		}
		return nil, keyStoreBackendStatus("list", err)
	}
	logger.Debugf("key-store list completed owner=%s prefix=%q count=%d", tenantNamespace(req.ClientId), prefix, len(names))
	return &proto.KeyStoreListResponse{Names: names}, nil
}

func (p *Plugin) keyStoreDeleteImpl(ctx context.Context, req *proto.KeyStoreDeleteRequest) (*proto.KeyStoreDeleteResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionDelete, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	if err := p.client.ensureKeyStoreSecretExists(ctx, req.ClientId, name); err != nil {
		return nil, keyStoreNotFoundOrBackendStatus("delete", err, "key-store entry not found")
	}
	if err := p.client.deleteKeyStoreSecret(ctx, req.ClientId, name); err != nil {
		return nil, keyStoreBackendStatus("delete", err)
	}
	logger.Debugf("key-store delete completed name=%s owner=%s", name, tenantNamespace(req.ClientId))
	return &proto.KeyStoreDeleteResponse{Name: name}, nil
}

func normalizeKeyStoreName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if len(name) > maxKeyStoreNameLen {
		return "", fmt.Errorf("name must be at most %d characters", maxKeyStoreNameLen)
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", fmt.Errorf("name must not start or end with /")
	}
	segments := strings.Split(name, "/")
	for _, segment := range segments {
		if err := validateKeyStoreSegment("name", segment); err != nil {
			return "", err
		}
	}
	return name, nil
}

func normalizeKeyStorePrefix(value string) (string, error) {
	prefix := strings.Trim(strings.TrimSpace(value), "/")
	if prefix == "" {
		return "", nil
	}
	if len(prefix) > maxKeyStoreNameLen {
		return "", fmt.Errorf("prefix must be at most %d characters", maxKeyStoreNameLen)
	}
	segments := strings.Split(prefix, "/")
	for _, segment := range segments {
		if err := validateKeyStoreSegment("prefix", segment); err != nil {
			return "", err
		}
	}
	return prefix, nil
}

func validateKeyStoreSegment(fieldName, segment string) error {
	if segment == "" || segment == "." || segment == ".." {
		return fmt.Errorf("%s contains an invalid path segment", fieldName)
	}
	if !keyStoreSegmentRe.MatchString(segment) {
		return fmt.Errorf("%s contains unsupported characters", fieldName)
	}
	return nil
}

func decodeKeyStoreSecretJSON(value string) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(value)))
	var secret json.RawMessage
	if err := decoder.Decode(&secret); err != nil {
		return nil, fmt.Errorf("secret must be a JSON object: %w", err)
	}
	if !isKeyStoreJSONObject(secret) {
		return nil, fmt.Errorf("secret must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("secret must contain exactly one JSON object")
	}
	return secret, nil
}

func encodeKeyStoreSecretJSON(record *keyStoreRecord) (string, error) {
	if secretJSON, ok := keyStoreRecordSecretJSON(record); ok {
		return secretJSON, nil
	}
	return "", fmt.Errorf("stored key-store secret must be a JSON object")
}

func isValidKeyStoreRecord(record *keyStoreRecord, clientID, name string) bool {
	_, hasValidSecret := keyStoreRecordSecretJSON(record)
	return record != nil &&
		record.Owner == tenantNamespace(clientID) &&
		record.Name == name &&
		hasValidSecret
}

func keyStoreRecordSecretJSON(record *keyStoreRecord) (string, bool) {
	if record == nil {
		return "", false
	}
	if strings.TrimSpace(record.SecretJSON) != "" {
		return record.SecretJSON, isKeyStoreJSONObject(json.RawMessage(record.SecretJSON))
	}
	return "", false
}

func isKeyStoreJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(trimmed)
}

func keyStoreNotFoundOrBackendStatus(operation string, err error, notFoundMessage string) error {
	if isOpenBaoStatus(err, http.StatusNotFound) {
		logKeyStoreOpenBaoError(operation, err)
		return status.Error(codes.NotFound, notFoundMessage)
	}
	return keyStoreBackendStatus(operation, err)
}

func keyStoreBackendStatus(operation string, err error) error {
	logKeyStoreOpenBaoError(operation, err)
	return status.Error(codes.Internal, "key-store backend error")
}

func isOpenBaoStatus(err error, statusCode int) bool {
	var statusErr *openbao.StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

func logKeyStoreOpenBaoError(operation string, err error) {
	var statusErr *openbao.StatusError
	if errors.As(err, &statusErr) {
		logger.Warnf(
			"key-store %s OpenBao backend error status_code=%d status=%q body=%q",
			operation,
			statusErr.StatusCode,
			statusErr.Status,
			statusErr.Body,
		)
		return
	}
	logger.Warnf("key-store %s backend error: %v", operation, err)
}

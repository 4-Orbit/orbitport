package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// AuditEvent is one authorization decision. It carries metadata only: never
// tokens, plaintext, ciphertext, key material, raw backend errors or Cedar
// diagnostic text. The shape follows 4Orbit's prototype-1/src/audit.ts with
// tenant, policy version and enforcement mode added.
type AuditEvent struct {
	Ts                  string     `json:"ts"`
	RequestID           string     `json:"requestId"`
	Tenant              string     `json:"tenant"`
	Principal           string     `json:"principal"`
	Action              string     `json:"action"`
	Resource            string     `json:"resource"`
	Decision            Decision   `json:"decision"`
	DeterminingPolicies []string   `json:"determiningPolicies"`
	AuthzErrors         []string   `json:"authzErrors,omitempty"`
	PolicyVersion       int64      `json:"policyVersion"`
	Mode                string     `json:"mode"`
	KmsCalled           bool       `json:"kmsCalled"`
	KmsOperation        string     `json:"kmsOperation,omitempty"`
	KmsResult           *KmsResult `json:"kmsResult,omitempty"`
	JtiHash             string     `json:"jtiHash,omitempty"`
}

// KmsResult records whether the backend call succeeded, with a stable error
// code only (backend messages are untrusted and may echo secrets).
type KmsResult struct {
	Status    string `json:"status"`
	ErrorCode string `json:"errorCode,omitempty"`
}

const (
	ModeEnforce = "enforce"
	ModeShadow  = "shadow"
)

var auditIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,255}$`)

// AuditUID renders an entity as Type::"id", replacing an unexpected identifier
// with <invalid> so arbitrary caller input never lands in the audit log.
func AuditUID(entityType, id string) string {
	if !auditIDRe.MatchString(id) {
		id = "<invalid>"
	}
	return entityType + `::"` + id + `"`
}

// PrincipalUID renders the Cedar principal of p.
func PrincipalUID(p Principal) string {
	if p.IsAgent() {
		return AuditUID("Agent", p.AgentID)
	}
	return AuditUID("Account", p.Tenant)
}

// HashJTI shortens a token id for audit correlation without storing it.
func HashJTI(jti string) string {
	if jti == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(sum[:8])
}

// AuthzErrorMarker is the only diagnostic recorded in audit events.
const AuthzErrorMarker = "AUTHORIZATION_ERROR"

// NewAuditEvent fills the decision fields of an event from a request/result.
func NewAuditEvent(ts, requestID string, req Request, res Result, version int64, mode string) AuditEvent {
	ev := AuditEvent{
		Ts:                  ts,
		RequestID:           requestID,
		Tenant:              req.Principal.Tenant,
		Principal:           PrincipalUID(req.Principal),
		Action:              AuditUID("Action", req.Action),
		Resource:            AuditUID(ResourceTypeFor(req.Action), req.Resource.ID),
		Decision:            res.Decision,
		DeterminingPolicies: append([]string{}, res.DeterminingPolicies...),
		PolicyVersion:       version,
		Mode:                mode,
	}
	if res.Errored {
		ev.AuthzErrors = []string{AuthzErrorMarker}
	}
	return ev
}

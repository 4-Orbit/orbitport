package policy

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
)

func appendJSONL(dir, key string, ev authz.AuditEvent) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, key+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		logger.Warnf("audit: cannot append to %s: %v", dir, err)
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Write(append(raw, '\n'))
}

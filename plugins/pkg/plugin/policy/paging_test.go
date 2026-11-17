package policy

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
)

// bundleN is a distinct, valid bundle per n.
func bundleN(n int) map[string]any {
	return map[string]any{"policies": fmt.Sprintf("@id(\"p%d\") permit (principal is Account, action, resource);", n), "message": fmt.Sprintf("v%d", n)}
}

func stores(t *testing.T) map[string]*Plugin {
	t.Helper()
	server := httptest.NewServer(&fakeKV{docs: map[string]kvDoc{}})
	t.Cleanup(server.Close)
	bao := newPlugin(newBaoStore(server.URL, "orbitport-policy", 5*time.Second), newAuditLog(10, ""))
	bao.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return map[string]*Plugin{"memory": newTestPlugin(t), "openbao": bao}
}

func TestListVersionsPagesThroughEverything(t *testing.T) {
	for name, p := range stores(t) {
		t.Run(name, func(t *testing.T) {
			const total = 250
			for i := 1; i <= total; i++ {
				mustCall(t, p, "policy.SaveDraft", bundleN(i))
			}
			mustCall(t, p, "policy.Activate", map[string]any{"version": 7})

			seen := map[float64]bool{}
			cursor := ""
			pages := 0
			for {
				params := map[string]any{"limit": 100}
				if cursor != "" {
					params["cursor"] = cursor
				}
				out := mustCall(t, p, "policy.ListVersions", params)
				pages++
				prev := float64(total + 1)
				for _, raw := range out["versions"].([]any) {
					v := raw.(map[string]any)
					n := v["version"].(float64)
					assert.Less(t, n, prev, "newest first, no repeats")
					prev = n
					assert.False(t, seen[n], "version %v listed twice", n)
					seen[n] = true
					assert.Equal(t, n == 7, v["active"], "active flag on v%v", n)
				}
				cursor = out["nextCursor"].(string)
				if cursor == "" {
					break
				}
				require.Less(t, pages, 10, "paging must terminate")
			}
			assert.Equal(t, 3, pages)
			assert.Len(t, seen, total, "every version is reachable")
		})
	}
}

func TestListVersionsLimitsAndCursorValidation(t *testing.T) {
	p := newTestPlugin(t)
	for i := 1; i <= 5; i++ {
		mustCall(t, p, "policy.SaveDraft", bundleN(i))
	}
	out := mustCall(t, p, "policy.ListVersions", map[string]any{"limit": 2})
	assert.Len(t, out["versions"], 2)
	assert.Equal(t, "4", out["nextCursor"])
	out = mustCall(t, p, "policy.ListVersions", map[string]any{"limit": 2, "cursor": "2"})
	assert.Len(t, out["versions"], 1, "only v1 is below 2")
	assert.Equal(t, "", out["nextCursor"])
	out = mustCall(t, p, "policy.ListVersions", map[string]any{})
	assert.Len(t, out["versions"], 5, "default limit covers small lists")
	for _, bad := range []string{"abc", "0", "-3"} {
		_, err := callAs(t, p, "", "policy.ListVersions", map[string]any{"cursor": bad})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), bad)
	}
}

func TestDuplicateCheckFindsVersionsOlderThanOnePage(t *testing.T) {
	for name, p := range stores(t) {
		t.Run(name, func(t *testing.T) {
			first := mustCall(t, p, "policy.SaveDraft", bundleN(0))
			for i := 1; i <= 150; i++ {
				mustCall(t, p, "policy.SaveDraft", bundleN(i))
			}
			again := mustCall(t, p, "policy.SaveDraft", bundleN(0))
			assert.Equal(t, true, again["duplicate"], "v1 is 150 versions back")
			assert.Equal(t, first["version"], again["version"])
		})
	}
}

func TestContentIndexBackfillsLegacyStore(t *testing.T) {
	kv := &fakeKV{docs: map[string]kvDoc{}}
	server := httptest.NewServer(kv)
	defer server.Close()
	store := newBaoStore(server.URL, "orbitport-policy", 5*time.Second)
	ctx := context.Background()

	// Versions written the pre-index way: no hashes/ entries, no marker.
	for i := 1; i <= 3; i++ {
		b := bundleN(i)
		_, err := store.SaveVersion(ctx, tenant, Version{Policies: b["policies"].(string)})
		require.NoError(t, err)
	}
	for k := range kv.docs {
		if strings.Contains(k, "/hashes/") || strings.Contains(k, "/hashindex") {
			delete(kv.docs, k)
		}
	}

	n, err := store.FindByContent(ctx, tenant, contentHash(bundleN(2)["policies"].(string), nil))
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "found after back-fill")
	_, marked := kv.docs["tenants/"+tenantKey(tenant)+"/hashindex"]
	assert.True(t, marked, "back-fill records completion")

	// A stale or corrupted entry never produces a false duplicate: the
	// plugin compares real content before trusting the index.
	p := newPlugin(store, newAuditLog(10, ""))
	other := authz.Bundle{Policies: bundleN(99)["policies"].(string)}
	kv.docs["tenants/"+tenantKey(tenant)+"/hashes/"+contentHash(other.Policies, nil)] = kvDoc{data: []byte(`{"version":1}`), version: 1}
	found, err := p.findIdentical(ctx, tenant, other)
	require.NoError(t, err)
	assert.EqualValues(t, 0, found)
}

func TestMatrixPagesKeysAndAgents(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	var keys []map[string]any
	for i := 0; i < 230; i++ {
		keys = append(keys, map[string]any{"id": fmt.Sprintf("k-%03d", i)})
	}
	// 230 + the 3 keys the template names = 233 keys, all reachable.
	seen := map[string]bool{}
	offset := 0
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		out := mustCall(t, p, "policy.Matrix", map[string]any{"keys": keys, "keyOffset": offset, "keyLimit": 100})
		assert.EqualValues(t, 233, out["totalKeys"])
		page := out["keys"].([]any)
		for _, k := range page {
			assert.False(t, seen[k.(string)], "key %v on two pages", k)
			seen[k.(string)] = true
		}
		assert.Len(t, out["cells"], 3*len(page)*len(authz.KeyActions), "cells only for this page")
		offset += len(page)
		if offset >= 233 {
			break
		}
	}
	assert.Len(t, seen, 233)

	out := mustCall(t, p, "policy.Matrix", map[string]any{"agentLimit": 2, "includeAccount": true})
	assert.EqualValues(t, 4, out["totalPrincipals"])
	assert.Len(t, out["principals"], 2)
	out = mustCall(t, p, "policy.Matrix", map[string]any{"agentOffset": 2, "agentLimit": 2, "includeAccount": true})
	assert.Equal(t, []any{"developer-agent", "security-agent"}, out["principals"])

	tooMany := make([]map[string]any, maxMatrixInputKeys+1)
	for i := range tooMany {
		tooMany[i] = map[string]any{"id": fmt.Sprintf("x%d", i)}
	}
	_, err := callAs(t, p, "", "policy.Matrix", map[string]any{"keys": tooMany})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func auditEvent(i int, agent string, d authz.Decision) authz.AuditEvent {
	return authz.AuditEvent{Tenant: tenant, RequestID: fmt.Sprintf("r%04d", i), Principal: authz.AuditUID("Agent", agent), Action: `Action::"kms.Encrypt"`, Resource: `Key::"dev-key"`, Decision: d}
}

func TestListAuditPagesWithFiltersBeforePaging(t *testing.T) {
	p := newPlugin(newMemStore(), newAuditLog(5000, ""))
	for i := 1; i <= 1000; i++ {
		agent, d := "developer-agent", authz.Allow
		if i%3 == 0 {
			agent, d = "security-agent", authz.Deny
		}
		p.audit.add(auditEvent(i, agent, d))
	}

	page := func(params map[string]any) (ids []string, next string) {
		out := mustCall(t, p, "policy.ListAudit", params)
		for _, e := range out["events"].([]any) {
			ids = append(ids, e.(map[string]any)["requestId"].(string))
		}
		return ids, out["nextCursor"].(string)
	}

	// Every DENY (333 of them, spread over the whole log) is reachable.
	var all []string
	cursor := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 20)
		params := map[string]any{"decision": "DENY", "limit": 50}
		if cursor != "" {
			params["cursor"] = cursor
		}
		ids, next := page(params)
		all = append(all, ids...)
		if next == "" {
			break
		}
		cursor = next
	}
	assert.Len(t, all, 333)
	assert.Equal(t, "r0999", all[0], "newest first")
	assert.Equal(t, "r0003", all[len(all)-1])
	unique := map[string]bool{}
	for _, id := range all {
		unique[id] = true
	}
	assert.Len(t, unique, 333, "no repeats across pages")

	// The last page reports no cursor even when it is exactly full.
	ids, next := page(map[string]any{"agentId": "security-agent", "limit": 200, "cursor": "13"})
	assert.Equal(t, []string{"r0012", "r0009", "r0006", "r0003"}, ids)
	assert.Equal(t, "", next)

	_, err := callAs(t, p, "", "policy.ListAudit", map[string]any{"cursor": "nope"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAuditCursorSurvivesRingEviction(t *testing.T) {
	log := newAuditLog(100, "")
	for i := 1; i <= 100; i++ {
		log.add(auditEvent(i, "a", authz.Allow))
	}
	first, cursor := log.list(tenant, auditFilter{Limit: 10})
	assert.Equal(t, "r0100", first[0].RequestID)
	// 30 new events push the 30 oldest out of the ring.
	for i := 101; i <= 130; i++ {
		log.add(auditEvent(i, "a", authz.Allow))
	}
	older, _ := log.list(tenant, auditFilter{Limit: 10, Cursor: cursor})
	assert.Equal(t, "r0090", older[0].RequestID, "the cursor still continues where the page ended")
}

func TestMatrixSummaryAndAgentFocus(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	var keys []map[string]any
	for i := 0; i < 230; i++ {
		keys = append(keys, map[string]any{"id": fmt.Sprintf("k-%03d", i)})
	}

	// Summary: exact counts over all 233 keys, no cells.
	out := mustCall(t, p, "policy.Matrix", map[string]any{"keys": keys, "summary": true})
	assert.EqualValues(t, 233, out["totalKeys"])
	assert.Nil(t, out["cells"])
	got := map[string]map[string]any{}
	for _, raw := range out["summary"].([]any) {
		s := raw.(map[string]any)
		got[s["principal"].(string)] = s
	}
	assert.EqualValues(t, 2, got["developer-agent"]["allowedKeys"])
	assert.EqualValues(t, 2, got["developer-agent"]["byAction"].(map[string]any)["kms.Encrypt"])
	assert.EqualValues(t, 3, got["security-agent"]["allowedKeys"])
	assert.EqualValues(t, 3, got["security-agent"]["byAction"].(map[string]any)["kms.RotateKey"])
	assert.EqualValues(t, 1, got["deployment-agent"]["allowedKeys"])
	assert.Equal(t, []any{"developer"}, got["developer-agent"]["roles"])

	// One agent, only the keys it can use: 2 keys, paged and counted as 2.
	focus := mustCall(t, p, "policy.Matrix", map[string]any{"keys": keys, "agents": []string{"developer-agent"}, "onlyAllowed": true})
	assert.Equal(t, []any{"developer-agent"}, focus["principals"])
	assert.EqualValues(t, 2, focus["totalKeys"])
	assert.Equal(t, []any{"demo-key", "dev-key"}, focus["keys"])

	// The same agent, every key, searched.
	search := mustCall(t, p, "policy.Matrix", map[string]any{"keys": keys, "agents": []string{"developer-agent"}, "keySearch": "K-01"})
	assert.EqualValues(t, 10, search["totalKeys"], "k-010..k-019, case-insensitive")

	// An agent with no access anywhere under onlyAllowed has zero keys.
	none := mustCall(t, p, "policy.Matrix", map[string]any{"keys": keys, "agents": []string{"ghost"}, "onlyAllowed": true})
	assert.EqualValues(t, 0, none["totalKeys"])
	assert.Empty(t, none["principals"])
}

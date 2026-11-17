package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestListKeysPagesWithoutDroppingKeys(t *testing.T) {
	p, bao, _ := newAgentTestPlugin(t, noPolicies{}, "enforce")
	for i := 0; i < 450; i++ {
		bao.keys[fmt.Sprintf("key-%04d", i)] = `[]`
	}
	total := len(bao.keys) // 450 plus the three fixture keys

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		resp, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: agentTestTenant, Cursor: cursor})
		require.NoError(t, err)
		pages++
		assert.LessOrEqual(t, len(resp.Keys), maxListedKeys)
		for _, k := range resp.Keys {
			assert.False(t, seen[k.Alias], "%s listed twice", k.Alias)
			seen[k.Alias] = true
		}
		assert.Equal(t, resp.NextCursor != "", resp.Truncated)
		if pages == 1 {
			// A key created mid-walk, sorting after the first page, still appears.
			bao.keys["zz-created-later"] = `[]`
			total++
		}
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
		require.Less(t, pages, 10)
	}
	assert.Equal(t, 3, pages)
	assert.Len(t, seen, total, "no key is silently dropped")
	assert.True(t, seen["zz-created-later"])
}

func TestListKeysHonoursLimit(t *testing.T) {
	p, _, _ := newAgentTestPlugin(t, noPolicies{}, "enforce")
	resp, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: agentTestTenant, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 2)
	assert.Equal(t, "kms:dev-key", resp.NextCursor, "cursor is the last returned key id")
	resp, err = p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: agentTestTenant, Cursor: resp.NextCursor, Limit: 2})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "prod-key", resp.Keys[0].Alias)
	assert.Empty(t, resp.NextCursor)
}

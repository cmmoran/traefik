package acmeredux

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultLockDoWithLockRejectsUnrelatedLocalCallerWhenHeld(t *testing.T) {
	vl := &vaultLock{
		OwnerID:  "owner-a",
		refCount: 1,
	}

	err := vl.DoWithLock(context.Background(), func(context.Context) error {
		return nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLockHeld)
	assert.Equal(t, 1, vl.refCount)
}

func TestVaultLockDoWithLockAllowsNestedContextWhenHeld(t *testing.T) {
	vl := &vaultLock{
		OwnerID:  "owner-a",
		refCount: 1,
	}

	ctx := withLockInfo(context.Background(), lockInfo{Owner: "owner-a"})
	called := false
	err := vl.DoWithLock(ctx, func(context.Context) error {
		called = true
		return nil
	})

	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, 1, vl.refCount)
}

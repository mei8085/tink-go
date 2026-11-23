// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyset_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/testing/protocmp"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// This file tests the key state contract that makes a local keyset
// rotatable: the readability window of old ciphertext and the key that owns
// new ciphertext are both decided by the state of the keys, not by the
// position of a key in the keyset.
//
// The scenarios cover a multi-key rotation (add a key, promote it to primary),
// disabling the old key and destroying it. They pin three invariants:
//
//   - Rejected state operations must not change the set of usable keys nor the
//     identity of the primary key.
//   - Old ciphertext stays readable for as long as the key that produced it is
//     enabled, and stops being readable once that key is disabled or
//     destroyed.
//   - New ciphertext is written with the current primary key, so a disabled
//     old key never takes part in new writes.

// rotationTestKey returns a test-only AEAD key with the given key ID and key
// material. Different seeds produce different key material, so ciphertexts
// written with one key cannot be decrypted with another.
func rotationTestKey(t *testing.T, keyID uint32, seed byte) *keytest.Key {
	t.Helper()
	params, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters(keytest.VariantTink) err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData(bytes.Repeat([]byte{seed}, 16), insecuresecretdataaccess.Token{})
	key, err := keytest.NewKey(keyBytes, keyID, params)
	if err != nil {
		t.Fatalf("keytest.NewKey(keyBytes, %d, params) err = %v, want nil", keyID, err)
	}
	return key
}

// mustAddRotationKey adds key to km with the given options and returns its key
// ID.
func mustAddRotationKey(t *testing.T, km *keyset.Manager, key key.Key, opts ...keyset.KeyOpts) uint32 {
	t.Helper()
	keyID, err := km.AddKeyWithOpts(key, internalapi.Token{}, opts...)
	if err != nil {
		t.Fatalf("km.AddKeyWithOpts() err = %v, want nil", err)
	}
	return keyID
}

// mustRotationHandle returns the handle of km, failing the test if km does not
// describe a valid keyset.
func mustRotationHandle(t *testing.T, km *keyset.Manager) *keyset.Handle {
	t.Helper()
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	return handle
}

// mustRotationAEAD returns an AEAD primitive built from handle.
func mustRotationAEAD(t *testing.T, handle *keyset.Handle) tink.AEAD {
	t.Helper()
	a, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}
	return a
}

// mustPrimaryKeyID returns the key ID of the primary key of handle.
func mustPrimaryKeyID(t *testing.T, handle *keyset.Handle) uint32 {
	t.Helper()
	entry, err := handle.Primary()
	if err != nil {
		t.Fatalf("handle.Primary() err = %v, want nil", err)
	}
	return entry.KeyID()
}

// enabledKeyIDs returns the sorted key IDs of the enabled entries of handle,
// that is, the set of keys that can produce or decrypt ciphertext.
func enabledKeyIDs(t *testing.T, handle *keyset.Handle) []uint32 {
	t.Helper()
	var keyIDs []uint32
	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("handle.Entry(%d) err = %v, want nil", i, err)
		}
		if entry.KeyStatus() == keyset.Enabled {
			keyIDs = append(keyIDs, entry.KeyID())
		}
	}
	slices.Sort(keyIDs)
	return keyIDs
}

// primaryKeyIDs returns the key IDs of the entries of handle that carry the
// primary flag.
func primaryKeyIDs(t *testing.T, handle *keyset.Handle) []uint32 {
	t.Helper()
	var keyIDs []uint32
	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("handle.Entry(%d) err = %v, want nil", i, err)
		}
		if entry.IsPrimary() {
			keyIDs = append(keyIDs, entry.KeyID())
		}
	}
	return keyIDs
}

// mustEntryStatus returns the status of the entry with the given key ID.
func mustEntryStatus(t *testing.T, handle *keyset.Handle, keyID uint32) keyset.KeyStatus {
	t.Helper()
	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("handle.Entry(%d) err = %v, want nil", i, err)
		}
		if entry.KeyID() == keyID {
			return entry.KeyStatus()
		}
	}
	t.Fatalf("handle with key IDs %v does not contain key ID %d", allKeyIDs(t, handle), keyID)
	return keyset.Unknown
}

// allKeyIDs returns the key IDs of the entries of handle in order.
func allKeyIDs(t *testing.T, handle *keyset.Handle) []uint32 {
	t.Helper()
	keyIDs := make([]uint32, 0, handle.Len())
	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("handle.Entry(%d) err = %v, want nil", i, err)
		}
		keyIDs = append(keyIDs, entry.KeyID())
	}
	return keyIDs
}

// entryState is the state of a keyset entry that must survive a rejected
// operation. The fields are exported so that the states can be compared with
// cmp.
type entryState struct {
	KeyID     uint32
	Status    keyset.KeyStatus
	IsPrimary bool
}

// entryStates returns the state of every entry of handle in order.
func entryStates(t *testing.T, handle *keyset.Handle) []entryState {
	t.Helper()
	states := make([]entryState, 0, handle.Len())
	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("handle.Entry(%d) err = %v, want nil", i, err)
		}
		states = append(states, entryState{
			KeyID:     entry.KeyID(),
			Status:    entry.KeyStatus(),
			IsPrimary: entry.IsPrimary(),
		})
	}
	return states
}

// mustEncrypt encrypts plaintext with a and fails the test on error.
func mustEncrypt(t *testing.T, a tink.AEAD, plaintext []byte) []byte {
	t.Helper()
	ciphertext, err := a.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("a.Encrypt(%q) err = %v, want nil", plaintext, err)
	}
	return ciphertext
}

// mustDecrypt decrypts ciphertext with a and returns the plaintext, failing
// the test on error.
func mustDecrypt(t *testing.T, a tink.AEAD, ciphertext []byte) []byte {
	t.Helper()
	plaintext, err := a.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext) err = %v, want nil", err)
	}
	return plaintext
}

// mustFailDecrypt asserts that a cannot decrypt ciphertext.
func mustFailDecrypt(t *testing.T, a tink.AEAD, ciphertext []byte) {
	t.Helper()
	plaintext, err := a.Decrypt(ciphertext, nil)
	if err == nil {
		t.Fatalf("a.Decrypt(ciphertext) = %q, want error", plaintext)
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("a.Decrypt(ciphertext) err = %q, want it to contain %q", err, "decryption failed")
	}
}

// mustHandleWithStatus returns a copy of handle in which the entry with keyID
// has the given status, as if the keyset had been loaded from storage where
// that key is marked accordingly.
func mustHandleWithStatus(t *testing.T, handle *keyset.Handle, keyID uint32, status tinkpb.KeyStatusType) *keyset.Handle {
	t.Helper()
	protoKeyset := testkeyset.KeysetMaterial(handle)
	found := false
	for _, protoKey := range protoKeyset.GetKey() {
		if protoKey.GetKeyId() == keyID {
			protoKey.Status = status
			found = true
		}
	}
	if !found {
		t.Fatalf("keyset does not contain key ID %d", keyID)
	}
	modified, err := testkeyset.NewHandle(protoKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(protoKeyset) err = %v, want nil", err)
	}
	return modified
}

// rotatedRotationManager builds a keyset midway through a rotation: oldKeyID is
// enabled but no longer primary, and newKeyID is enabled and primary.
//
// It returns the manager together with the keys, so that tests can check which
// key owns a ciphertext by comparing its output prefix.
func rotatedRotationManager(t *testing.T) (km *keyset.Manager, oldKey, newKey *keytest.Key, oldKeyID, newKeyID uint32) {
	t.Helper()
	km = keyset.NewManager()
	oldKey = rotationTestKey(t, 1, 0x11)
	newKey = rotationTestKey(t, 2, 0x22)
	oldKeyID = mustAddRotationKey(t, km, oldKey, keyset.WithFixedID(1), keyset.AsPrimary())
	newKeyID = mustAddRotationKey(t, km, newKey, keyset.WithFixedID(2))
	if err := km.SetPrimary(newKeyID); err != nil {
		t.Fatalf("km.SetPrimary(%d) err = %v, want nil", newKeyID, err)
	}
	return km, oldKey, newKey, oldKeyID, newKeyID
}

func TestKeysetRotation_MultiKeyStateTransitions(t *testing.T) {
	key1 := rotationTestKey(t, 1, 0x11)
	key2 := rotationTestKey(t, 2, 0x22)
	key3 := rotationTestKey(t, 3, 0x33)

	km := keyset.NewManager()
	if got, want := mustAddRotationKey(t, km, key1, keyset.WithFixedID(1), keyset.AsPrimary()), uint32(1); got != want {
		t.Fatalf("AddKeyWithOpts(key1) = %d, want %d", got, want)
	}

	assertState := func(wantPrimary uint32, wantEnabled []uint32) {
		t.Helper()
		handle := mustRotationHandle(t, km)
		if got := mustPrimaryKeyID(t, handle); got != wantPrimary {
			t.Errorf("handle.Primary().KeyID() = %d, want %d", got, wantPrimary)
		}
		if got := enabledKeyIDs(t, handle); !slices.Equal(got, wantEnabled) {
			t.Errorf("enabledKeyIDs(handle) = %v, want %v", got, wantEnabled)
		}
		if got := handle.KeysetInfo().GetPrimaryKeyId(); got != wantPrimary {
			t.Errorf("handle.KeysetInfo().GetPrimaryKeyId() = %d, want %d", got, wantPrimary)
		}
		// Promotion is exclusive: at most one entry may carry the primary
		// flag, even though a keyset proto records only a single primary key
		// ID.
		if got, want := primaryKeyIDs(t, handle), []uint32{wantPrimary}; !slices.Equal(got, want) {
			t.Errorf("primaryKeyIDs(handle) = %v, want %v", got, want)
		}
	}

	assertState(1, []uint32{1})

	// A second key is added enabled but not primary: it becomes usable for
	// decryption without taking over new writes.
	if got, want := mustAddRotationKey(t, km, key2, keyset.WithFixedID(2)), uint32(2); got != want {
		t.Fatalf("AddKeyWithOpts(key2) = %d, want %d", got, want)
	}
	assertState(1, []uint32{1, 2})

	// Promotion moves new writes to the new key.
	if err := km.SetPrimary(2); err != nil {
		t.Fatalf("km.SetPrimary(2) err = %v, want nil", err)
	}
	assertState(2, []uint32{1, 2})

	// A third key may join the rotation as primary without affecting the
	// availability of the other keys.
	if got, want := mustAddRotationKey(t, km, key3, keyset.WithFixedID(3), keyset.AsPrimary()), uint32(3); got != want {
		t.Fatalf("AddKeyWithOpts(key3) = %d, want %d", got, want)
	}
	assertState(3, []uint32{1, 2, 3})

	// Disabling a non-primary key removes it from the usable set and leaves
	// the primary untouched.
	if err := km.Disable(1); err != nil {
		t.Fatalf("km.Disable(1) err = %v, want nil", err)
	}
	assertState(3, []uint32{2, 3})

	// Re-enabling a disabled key restores it and still does not change the
	// primary.
	if err := km.Enable(1); err != nil {
		t.Fatalf("km.Enable(1) err = %v, want nil", err)
	}
	assertState(3, []uint32{1, 2, 3})

	// Rotation back to an older key is allowed while it is enabled.
	if err := km.SetPrimary(1); err != nil {
		t.Fatalf("km.SetPrimary(1) err = %v, want nil", err)
	}
	assertState(1, []uint32{1, 2, 3})
}

func TestKeysetRotation_OldCiphertextWindowFollowsKeyStatus(t *testing.T) {
	km := keyset.NewManager()
	oldKey := rotationTestKey(t, 1, 0x11)
	mustAddRotationKey(t, km, oldKey, keyset.WithFixedID(1), keyset.AsPrimary())
	oldPlaintext := []byte("data encrypted before the rotation")
	oldCiphertext := mustEncrypt(t, mustRotationAEAD(t, mustRotationHandle(t, km)), oldPlaintext)

	// Rotate: a fresh key is added and promoted while the old key stays
	// enabled.
	newKey := rotationTestKey(t, 2, 0x22)
	mustAddRotationKey(t, km, newKey, keyset.WithFixedID(2))
	if err := km.SetPrimary(2); err != nil {
		t.Fatalf("km.SetPrimary(2) err = %v, want nil", err)
	}
	rotatedHandle := mustRotationHandle(t, km)
	rotatedAEAD := mustRotationAEAD(t, rotatedHandle)

	// The old key is still enabled, so ciphertext written before the rotation
	// is still readable.
	if got := mustDecrypt(t, rotatedAEAD, oldCiphertext); !bytes.Equal(got, oldPlaintext) {
		t.Errorf("rotatedAEAD.Decrypt(oldCiphertext) = %q, want %q", got, oldPlaintext)
	}

	// New writes are attributed to the new primary key.
	newPlaintext := []byte("data encrypted after the rotation")
	newCiphertext := mustEncrypt(t, rotatedAEAD, newPlaintext)
	if !bytes.HasPrefix(newCiphertext, newKey.OutputPrefix()) {
		t.Errorf("newCiphertext has prefix %x, want the prefix of the new primary key %x", newCiphertext[:len(newKey.OutputPrefix())], newKey.OutputPrefix())
	}
	if bytes.HasPrefix(newCiphertext, oldKey.OutputPrefix()) {
		t.Errorf("newCiphertext has the prefix of the old key %x, want the prefix of the new primary key", oldKey.OutputPrefix())
	}

	// Disabling the old key closes its readability window without touching
	// the new key.
	if err := km.Disable(1); err != nil {
		t.Fatalf("km.Disable(1) err = %v, want nil", err)
	}
	handleAfterDisable := mustRotationHandle(t, km)
	if got, want := mustPrimaryKeyID(t, handleAfterDisable), uint32(2); got != want {
		t.Errorf("handle.Primary().KeyID() after disabling the old key = %d, want %d", got, want)
	}
	if got, want := enabledKeyIDs(t, handleAfterDisable), []uint32{2}; !slices.Equal(got, want) {
		t.Errorf("enabledKeyIDs(handle) after disabling the old key = %v, want %v", got, want)
	}
	if got := mustEntryStatus(t, handleAfterDisable, 1); got != keyset.Disabled {
		t.Errorf("old key status = %v, want %v", got, keyset.Disabled)
	}
	aeadAfterDisable := mustRotationAEAD(t, handleAfterDisable)
	mustFailDecrypt(t, aeadAfterDisable, oldCiphertext)
	if got := mustDecrypt(t, aeadAfterDisable, newCiphertext); !bytes.Equal(got, newPlaintext) {
		t.Errorf("aeadAfterDisable.Decrypt(newCiphertext) = %q, want %q", got, newPlaintext)
	}
	moreCiphertext := mustEncrypt(t, aeadAfterDisable, []byte("more data"))
	if !bytes.HasPrefix(moreCiphertext, newKey.OutputPrefix()) {
		t.Errorf("ciphertext written after disabling the old key has prefix %x, want %x", moreCiphertext[:len(newKey.OutputPrefix())], newKey.OutputPrefix())
	}

	// Enabling the old key again is a legal transition and reopens the window.
	if err := km.Enable(1); err != nil {
		t.Fatalf("km.Enable(1) err = %v, want nil", err)
	}
	handleAfterEnable := mustRotationHandle(t, km)
	if got, want := enabledKeyIDs(t, handleAfterEnable), []uint32{1, 2}; !slices.Equal(got, want) {
		t.Errorf("enabledKeyIDs(handle) after re-enabling the old key = %v, want %v", got, want)
	}
	if got := mustPrimaryKeyID(t, handleAfterEnable); got != 2 {
		t.Errorf("handle.Primary().KeyID() after re-enabling the old key = %d, want 2", got)
	}
	if got := mustDecrypt(t, mustRotationAEAD(t, handleAfterEnable), oldCiphertext); !bytes.Equal(got, oldPlaintext) {
		t.Errorf("AEAD after re-enabling the old key decrypts oldCiphertext to %q, want %q", got, oldPlaintext)
	}
}

func TestKeysetRotation_NewCiphertextIsOwnedByPrimaryKey(t *testing.T) {
	km, oldKey, newKey, _, newKeyID := rotatedRotationManager(t)

	// A handle taken before the rotation stands in for a reader that has not
	// picked up the new key yet.
	oldOnlyManager := keyset.NewManager()
	mustAddRotationKey(t, oldOnlyManager, oldKey, keyset.WithFixedID(1), keyset.AsPrimary())
	oldOnlyAEAD := mustRotationAEAD(t, mustRotationHandle(t, oldOnlyManager))

	rotatedAEAD := mustRotationAEAD(t, mustRotationHandle(t, km))
	plaintext := []byte("plaintext")
	ciphertext := mustEncrypt(t, rotatedAEAD, plaintext)

	// The ciphertext names the new primary key, not the old one.
	if got, want := ciphertext[:len(newKey.OutputPrefix())], newKey.OutputPrefix(); !bytes.Equal(got, want) {
		t.Errorf("ciphertext prefix = %x, want the prefix of the primary key %x", got, want)
	}
	if bytes.HasPrefix(ciphertext, oldKey.OutputPrefix()) {
		t.Errorf("ciphertext has the prefix of the old key %x, want the prefix of primary key %d", oldKey.OutputPrefix(), newKeyID)
	}

	// A keyset that only knows the old key cannot read it: the new data
	// belongs to the new key.
	mustFailDecrypt(t, oldOnlyAEAD, ciphertext)
	if got := mustDecrypt(t, rotatedAEAD, ciphertext); !bytes.Equal(got, plaintext) {
		t.Errorf("rotatedAEAD.Decrypt(ciphertext) = %q, want %q", got, plaintext)
	}
}

func TestKeysetRotation_DestroyedOldKeyClosesWindowAndCannotBePrimary(t *testing.T) {
	km, oldKey, newKey, oldKeyID, newKeyID := rotatedRotationManager(t)

	// The old ciphertext is produced by the old key alone, as it would have
	// been before the rotation.
	oldOnlyManager := keyset.NewManager()
	mustAddRotationKey(t, oldOnlyManager, oldKey, keyset.WithFixedID(1), keyset.AsPrimary())
	oldPlaintext := []byte("old plaintext")
	oldCiphertext := mustEncrypt(t, mustRotationAEAD(t, mustRotationHandle(t, oldOnlyManager)), oldPlaintext)
	newCiphertext := mustEncrypt(t, mustRotationAEAD(t, mustRotationHandle(t, km)), []byte("new plaintext"))

	// While the old key is enabled, the rotated keyset reads the old
	// ciphertext.
	if got := mustDecrypt(t, mustRotationAEAD(t, mustRotationHandle(t, km)), oldCiphertext); !bytes.Equal(got, oldPlaintext) {
		t.Errorf("rotated AEAD decrypts oldCiphertext to %q, want %q", got, oldPlaintext)
	}

	// Simulate the old key being destroyed by storage: the entry stays in the
	// keyset, but marked DESTROYED.
	destroyedHandle := mustHandleWithStatus(t, mustRotationHandle(t, km), oldKeyID, tinkpb.KeyStatusType_DESTROYED)

	if got, want := mustEntryStatus(t, destroyedHandle, oldKeyID), keyset.Destroyed; got != want {
		t.Errorf("old key status = %v, want %v", got, want)
	}
	if got, want := mustPrimaryKeyID(t, destroyedHandle), newKeyID; got != want {
		t.Errorf("handle.Primary().KeyID() = %d, want %d", got, want)
	}
	if got, want := enabledKeyIDs(t, destroyedHandle), []uint32{newKeyID}; !slices.Equal(got, want) {
		t.Errorf("enabledKeyIDs(handle) = %v, want %v", got, want)
	}

	a := mustRotationAEAD(t, destroyedHandle)
	mustFailDecrypt(t, a, oldCiphertext)
	if got, want := mustDecrypt(t, a, newCiphertext), []byte("new plaintext"); !bytes.Equal(got, want) {
		t.Errorf("a.Decrypt(newCiphertext) = %q, want %q", got, want)
	}
	ciphertext := mustEncrypt(t, a, []byte("after destruction"))
	if !bytes.HasPrefix(ciphertext, newKey.OutputPrefix()) {
		t.Errorf("ciphertext prefix = %x, want the prefix of the primary key %x", ciphertext[:len(newKey.OutputPrefix())], newKey.OutputPrefix())
	}
	if bytes.HasPrefix(ciphertext, oldKey.OutputPrefix()) {
		t.Errorf("destroyed old key took part in a new write, prefix = %x", oldKey.OutputPrefix())
	}

	// A destroyed key cannot be revived or promoted, and rejected operations
	// leave the keyset untouched.
	destroyedManager := keyset.NewManagerFromHandle(destroyedHandle)
	for _, tc := range []struct {
		name string
		op   func() error
	}{
		{name: "Enable", op: func() error { return destroyedManager.Enable(oldKeyID) }},
		{name: "SetPrimary", op: func() error { return destroyedManager.SetPrimary(oldKeyID) }},
		{name: "Disable", op: func() error { return destroyedManager.Disable(oldKeyID) }},
	} {
		t.Run(tc.name+"DestroyedKeyFails", func(t *testing.T) {
			before := mustRotationHandle(t, destroyedManager)
			beforeStates := entryStates(t, before)
			beforeInfo := before.KeysetInfo()

			if err := tc.op(); err == nil {
				t.Fatalf("operation on a destroyed key succeeded, want error")
			}
			after := mustRotationHandle(t, destroyedManager)
			if diff := cmp.Diff(beforeStates, entryStates(t, after)); diff != "" {
				t.Errorf("entries changed after a rejected operation (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(beforeInfo, after.KeysetInfo(), protocmp.Transform()); diff != "" {
				t.Errorf("keyset info changed after a rejected operation (-want +got):\n%s", diff)
			}
			if got := mustPrimaryKeyID(t, after); got != newKeyID {
				t.Errorf("handle.Primary().KeyID() = %d, want %d", got, newKeyID)
			}
		})
	}

	// Deleting the destroyed key is legal cleanup and keeps the new key
	// primary and usable.
	if err := destroyedManager.Delete(oldKeyID); err != nil {
		t.Fatalf("destroyedManager.Delete(oldKeyID) err = %v, want nil", err)
	}
	cleanedUpHandle := mustRotationHandle(t, destroyedManager)
	if got, want := allKeyIDs(t, cleanedUpHandle), []uint32{newKeyID}; !slices.Equal(got, want) {
		t.Errorf("key IDs after deleting the destroyed key = %v, want %v", got, want)
	}
	if got := mustPrimaryKeyID(t, cleanedUpHandle); got != newKeyID {
		t.Errorf("handle.Primary().KeyID() after deleting the destroyed key = %d, want %d", got, newKeyID)
	}
	cleanedUpAEAD := mustRotationAEAD(t, cleanedUpHandle)
	mustFailDecrypt(t, cleanedUpAEAD, oldCiphertext)
	if got := mustDecrypt(t, cleanedUpAEAD, newCiphertext); !bytes.Equal(got, []byte("new plaintext")) {
		t.Errorf("cleanedUpAEAD.Decrypt(newCiphertext) = %q, want %q", got, "new plaintext")
	}
}

func TestKeysetRotation_RejectedOperationsLeaveUsableKeysAndPrimaryUnchanged(t *testing.T) {
	// buildManager returns a keyset with two enabled keys (2 is primary) and a
	// third key in the given status.
	buildManager := func(t *testing.T, thirdStatus keyset.KeyStatus) *keyset.Manager {
		t.Helper()
		km := keyset.NewManager()
		mustAddRotationKey(t, km, rotationTestKey(t, 1, 0x11), keyset.WithFixedID(1))
		mustAddRotationKey(t, km, rotationTestKey(t, 2, 0x22), keyset.WithFixedID(2), keyset.AsPrimary())
		mustAddRotationKey(t, km, rotationTestKey(t, 3, 0x33), keyset.WithFixedID(3), keyset.WithStatus(thirdStatus))
		return km
	}

	for _, tc := range []struct {
		name        string
		thirdStatus keyset.KeyStatus
		op          func(t *testing.T, km *keyset.Manager) error
	}{
		{
			name:        "set primary to a disabled key",
			thirdStatus: keyset.Disabled,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.SetPrimary(3) },
		},
		{
			name:        "set primary to a destroyed key",
			thirdStatus: keyset.Destroyed,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.SetPrimary(3) },
		},
		{
			name:        "set primary to a missing key",
			thirdStatus: keyset.Enabled,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.SetPrimary(99) },
		},
		{
			name:        "disable the primary key",
			thirdStatus: keyset.Enabled,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.Disable(2) },
		},
		{
			name:        "enable a destroyed key",
			thirdStatus: keyset.Destroyed,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.Enable(3) },
		},
		{
			name:        "disable a destroyed key",
			thirdStatus: keyset.Destroyed,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.Disable(3) },
		},
		{
			name:        "delete the primary key",
			thirdStatus: keyset.Enabled,
			op:          func(_ *testing.T, km *keyset.Manager) error { return km.Delete(2) },
		},
		{
			name:        "add a disabled key as primary",
			thirdStatus: keyset.Enabled,
			op: func(t *testing.T, km *keyset.Manager) error {
				_, err := km.AddKeyWithOpts(rotationTestKey(t, 4, 0x44), internalapi.Token{}, keyset.WithFixedID(4), keyset.WithStatus(keyset.Disabled), keyset.AsPrimary())
				return err
			},
		},
		{
			name:        "add a destroyed key as primary",
			thirdStatus: keyset.Enabled,
			op: func(t *testing.T, km *keyset.Manager) error {
				_, err := km.AddKeyWithOpts(rotationTestKey(t, 4, 0x44), internalapi.Token{}, keyset.WithFixedID(4), keyset.WithStatus(keyset.Destroyed), keyset.AsPrimary())
				return err
			},
		},
		{
			name:        "add a key with an unknown status",
			thirdStatus: keyset.Enabled,
			op: func(t *testing.T, km *keyset.Manager) error {
				_, err := km.AddKeyWithOpts(rotationTestKey(t, 4, 0x44), internalapi.Token{}, keyset.WithFixedID(4), keyset.WithStatus(keyset.Unknown))
				return err
			},
		},
		{
			name:        "add a key whose ID is already in use",
			thirdStatus: keyset.Enabled,
			op: func(t *testing.T, km *keyset.Manager) error {
				// A second key with the same ID requirement and fixed ID as an
				// existing key must be rejected without disturbing it.
				_, err := km.AddKeyWithOpts(rotationTestKey(t, 2, 0x44), internalapi.Token{}, keyset.WithFixedID(2))
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km := buildManager(t, tc.thirdStatus)
			before := mustRotationHandle(t, km)
			beforeStates := entryStates(t, before)
			beforeInfo := before.KeysetInfo()
			beforeEnabled := enabledKeyIDs(t, before)
			beforePrimary := mustPrimaryKeyID(t, before)

			if err := tc.op(t, km); err == nil {
				t.Fatalf("operation succeeded, want error")
			}

			// A rejected operation must leave a valid keyset behind.
			after := mustRotationHandle(t, km)
			if diff := cmp.Diff(beforeStates, entryStates(t, after)); diff != "" {
				t.Errorf("entries changed after a rejected operation (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(beforeInfo, after.KeysetInfo(), protocmp.Transform()); diff != "" {
				t.Errorf("keyset info changed after a rejected operation (-want +got):\n%s", diff)
			}
			if got := enabledKeyIDs(t, after); !slices.Equal(got, beforeEnabled) {
				t.Errorf("enabledKeyIDs(handle) after a rejected operation = %v, want %v", got, beforeEnabled)
			}
			if got := mustPrimaryKeyID(t, after); got != beforePrimary {
				t.Errorf("handle.Primary().KeyID() after a rejected operation = %d, want %d", got, beforePrimary)
			}
		})
	}
}

func TestKeysetRotation_PublicHandleKeepsPrimaryIdentity(t *testing.T) {
	params, err := keytest.NewAsymmetricParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewAsymmetricParameters(keytest.VariantTink) err = %v, want nil", err)
	}
	privateKey := func(t *testing.T, keyID uint32, seed byte) *keytest.PrivateKey {
		t.Helper()
		keyBytes := secretdata.NewBytesFromData(bytes.Repeat([]byte{seed}, 16), insecuresecretdataaccess.Token{})
		key, err := keytest.NewPrivateKey(keyBytes, keyID, params)
		if err != nil {
			t.Fatalf("keytest.NewPrivateKey(keyBytes, %d, params) err = %v, want nil", keyID, err)
		}
		return key
	}

	km := keyset.NewManager()
	oldKeyID := mustAddRotationKey(t, km, privateKey(t, 1, 0x11), keyset.WithFixedID(1), keyset.AsPrimary())
	if err := km.SetPrimary(oldKeyID); err != nil {
		t.Fatalf("km.SetPrimary(%d) err = %v, want nil", oldKeyID, err)
	}

	// Snapshot the public handle before the rotation.
	publicBeforeRotation, err := mustRotationHandle(t, km).Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	if got, want := mustPrimaryKeyID(t, publicBeforeRotation), oldKeyID; got != want {
		t.Errorf("public handle primary key ID before rotation = %d, want %d", got, want)
	}
	if got, want := allKeyIDs(t, publicBeforeRotation), []uint32{oldKeyID}; !slices.Equal(got, want) {
		t.Errorf("public handle key IDs before rotation = %v, want %v", got, want)
	}

	// Rotate to a new key.
	newKeyID := mustAddRotationKey(t, km, privateKey(t, 2, 0x22), keyset.WithFixedID(2))
	if err := km.SetPrimary(newKeyID); err != nil {
		t.Fatalf("km.SetPrimary(%d) err = %v, want nil", newKeyID, err)
	}

	publicAfterRotation, err := mustRotationHandle(t, km).Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	if got, want := mustPrimaryKeyID(t, publicAfterRotation), newKeyID; got != want {
		t.Errorf("public handle primary key ID after rotation = %d, want %d", got, want)
	}
	if got, want := allKeyIDs(t, publicAfterRotation), []uint32{oldKeyID, newKeyID}; !slices.Equal(got, want) {
		t.Errorf("public handle key IDs after rotation = %v, want %v", got, want)
	}

	// The old snapshot keeps naming the old key: rotating the manager does not
	// rewrite handles that were handed out earlier.
	if got, want := mustPrimaryKeyID(t, publicBeforeRotation), oldKeyID; got != want {
		t.Errorf("public handle snapshot primary key ID = %d, want %d", got, want)
	}
	if got, want := allKeyIDs(t, publicBeforeRotation), []uint32{oldKeyID}; !slices.Equal(got, want) {
		t.Errorf("public handle snapshot key IDs = %v, want %v", got, want)
	}

	// Disabling the old key keeps the new key as primary and only flips the
	// old key's status in the public handle.
	if err := km.Disable(oldKeyID); err != nil {
		t.Fatalf("km.Disable(%d) err = %v, want nil", oldKeyID, err)
	}
	publicAfterDisable, err := mustRotationHandle(t, km).Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	if got, want := mustPrimaryKeyID(t, publicAfterDisable), newKeyID; got != want {
		t.Errorf("public handle primary key ID after disabling the old key = %d, want %d", got, want)
	}
	if got, want := mustEntryStatus(t, publicAfterDisable, oldKeyID), keyset.Disabled; got != want {
		t.Errorf("public handle old key status = %v, want %v", got, want)
	}

	// A rejected operation on the private keyset does not change the primary
	// identity of the public handle either.
	if err := km.Disable(newKeyID); err == nil {
		t.Fatalf("km.Disable(primary key) succeeded, want error")
	}
	publicAfterRejectedOp, err := mustRotationHandle(t, km).Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	if got, want := mustPrimaryKeyID(t, publicAfterRejectedOp), newKeyID; got != want {
		t.Errorf("public handle primary key ID after a rejected operation = %d, want %d", got, want)
	}
	if diff := cmp.Diff(entryStates(t, publicAfterDisable), entryStates(t, publicAfterRejectedOp)); diff != "" {
		t.Errorf("public handle entries changed after a rejected operation (-want +got):\n%s", diff)
	}
}

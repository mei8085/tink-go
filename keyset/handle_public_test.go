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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"
)

const (
	firstKeyID    = uint32(11)
	disabledKeyID = uint32(22)
	rotatedKeyID  = uint32(33)
	failingKeyID  = uint32(44)
)

// ed25519KeyPair holds a freshly generated ed25519 key pair in the shapes
// expected by the tinked25519 constructors.
type ed25519KeyPair struct {
	publicKeyBytes []byte
	// seed is the 32-byte private key seed accepted by NewPrivateKey.
	seed []byte
}

func mustGenerateEd25519KeyPair(t *testing.T) ed25519KeyPair {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(rand.Reader) err = %v, want nil", err)
	}
	return ed25519KeyPair{
		publicKeyBytes: []byte(publicKey),
		seed:           privateKey.Seed(),
	}
}

func tinkOutputPrefix(keyID uint32) []byte {
	prefix := make([]byte, 5)
	prefix[0] = cryptofmt.TinkStartByte
	binary.BigEndian.PutUint32(prefix[1:], keyID)
	return prefix
}

// mustAddEd25519PrivateKey builds an ed25519 private key with the given fixed
// ID and adds it to the manager.
func mustAddEd25519PrivateKey(t *testing.T, manager *keyset.Manager, id uint32, status keyset.KeyStatus, isPrimary bool) *tinked25519.PrivateKey {
	t.Helper()
	params, err := tinked25519.NewParameters(tinked25519.VariantTink)
	if err != nil {
		t.Fatalf("tinked25519.NewParameters() err = %v, want nil", err)
	}
	keyPair := mustGenerateEd25519KeyPair(t)
	publicKey, err := tinked25519.NewPublicKey(keyPair.publicKeyBytes, id, params)
	if err != nil {
		t.Fatalf("tinked25519.NewPublicKey() err = %v, want nil", err)
	}
	privateKey, err := tinked25519.NewPrivateKeyWithPublicKey(
		secretdata.NewBytesFromData(keyPair.seed, insecuresecretdataaccess.Token{}), publicKey)
	if err != nil {
		t.Fatalf("tinked25519.NewPrivateKeyWithPublicKey() err = %v, want nil", err)
	}
	opts := []keyset.KeyOpts{keyset.WithFixedID(id), keyset.WithStatus(status)}
	if isPrimary {
		opts = append(opts, keyset.AsPrimary())
	}
	if _, err := manager.AddKeyWithOpts(privateKey, internalapi.Token{}, opts...); err != nil {
		t.Fatalf("manager.AddKeyWithOpts() err = %v, want nil", err)
	}
	return privateKey
}

// mustCreateMultiKeyPrivateHandle creates a private keyset handle with three
// ed25519 keys:
//   - firstKeyID: enabled and primary;
//   - disabledKeyID: disabled;
//   - rotatedKeyID: enabled, used to rotate the primary key in the tests.
func mustCreateMultiKeyPrivateHandle(t *testing.T) *keyset.Handle {
	t.Helper()
	manager := keyset.NewManager()
	mustAddEd25519PrivateKey(t, manager, firstKeyID, keyset.Enabled, true)
	mustAddEd25519PrivateKey(t, manager, disabledKeyID, keyset.Disabled, false)
	mustAddEd25519PrivateKey(t, manager, rotatedKeyID, keyset.Enabled, false)
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	return handle
}

// failingPublicKeyPrivateKey wraps a valid private key but refuses to export
// its public key. It implements the unexported privateKey interface probed by
// [keyset.Handle.Public].
type failingPublicKeyPrivateKey struct {
	inner *tinked25519.PrivateKey
}

var _ key.Key = (*failingPublicKeyPrivateKey)(nil)

func (k *failingPublicKeyPrivateKey) Parameters() key.Parameters { return k.inner.Parameters() }

func (k *failingPublicKeyPrivateKey) IDRequirement() (uint32, bool) {
	return k.inner.IDRequirement()
}

func (k *failingPublicKeyPrivateKey) Equal(other key.Key) bool {
	that, ok := other.(*failingPublicKeyPrivateKey)
	return ok && that != nil && k.inner.Equal(that.inner)
}

// PublicKey always fails, so [keyset.Handle.Public] cannot complete.
func (k *failingPublicKeyPrivateKey) PublicKey() (key.Key, error) {
	return nil, fmt.Errorf("test-only key does not allow exporting the public key")
}

func mustAddFailingPrivateKey(t *testing.T, manager *keyset.Manager, id uint32) {
	t.Helper()
	params, err := tinked25519.NewParameters(tinked25519.VariantTink)
	if err != nil {
		t.Fatalf("tinked25519.NewParameters() err = %v, want nil", err)
	}
	keyPair := mustGenerateEd25519KeyPair(t)
	publicKey, err := tinked25519.NewPublicKey(keyPair.publicKeyBytes, id, params)
	if err != nil {
		t.Fatalf("tinked25519.NewPublicKey() err = %v, want nil", err)
	}
	inner, err := tinked25519.NewPrivateKeyWithPublicKey(
		secretdata.NewBytesFromData(keyPair.seed, insecuresecretdataaccess.Token{}), publicKey)
	if err != nil {
		t.Fatalf("tinked25519.NewPrivateKeyWithPublicKey() err = %v, want nil", err)
	}
	if _, err := manager.AddKeyWithOpts(
		&failingPublicKeyPrivateKey{inner: inner},
		internalapi.Token{},
		keyset.WithFixedID(id),
	); err != nil {
		t.Fatalf("manager.AddKeyWithOpts() err = %v, want nil", err)
	}
}

func mustRotatePrimary(t *testing.T, handle *keyset.Handle, newPrimaryID uint32) *keyset.Handle {
	t.Helper()
	manager := keyset.NewManagerFromHandle(handle)
	if err := manager.SetPrimary(newPrimaryID); err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", newPrimaryID, err)
	}
	rotated, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	return rotated
}

// TestPublicPreservesKeyIdentityAcrossRotation verifies that Handle.Public
// keeps the key identity of every entry: key IDs, primary flag, statuses,
// output prefixes and the public key material itself are preserved, including
// after the primary key is rotated in a multi-key asymmetric keyset.
func TestPublicPreservesKeyIdentityAcrossRotation(t *testing.T) {
	privateHandle := mustCreateMultiKeyPrivateHandle(t)
	rotatedPrivateHandle := mustRotatePrimary(t, privateHandle, rotatedKeyID)

	publicHandle, err := rotatedPrivateHandle.Public()
	if err != nil {
		t.Fatalf("rotatedPrivateHandle.Public() err = %v, want nil", err)
	}
	if got, want := publicHandle.Len(), rotatedPrivateHandle.Len(); got != want {
		t.Fatalf("publicHandle.Len() = %v, want %v", got, want)
	}

	wantIDs := []uint32{firstKeyID, disabledKeyID, rotatedKeyID}
	wantStatuses := []keyset.KeyStatus{keyset.Enabled, keyset.Disabled, keyset.Enabled}
	wantPrimary := []bool{false, false, true}
	for i := 0; i < rotatedPrivateHandle.Len(); i++ {
		privateEntry, err := rotatedPrivateHandle.Entry(i)
		if err != nil {
			t.Fatalf("rotatedPrivateHandle.Entry(%v) err = %v, want nil", i, err)
		}
		publicEntry, err := publicHandle.Entry(i)
		if err != nil {
			t.Fatalf("publicHandle.Entry(%v) err = %v, want nil", i, err)
		}
		if got, want := publicEntry.KeyID(), wantIDs[i]; got != want {
			t.Errorf("publicHandle.Entry(%v).KeyID() = %v, want %v", i, got, want)
		}
		if got, want := publicEntry.KeyStatus(), wantStatuses[i]; got != want {
			t.Errorf("publicHandle.Entry(%v).KeyStatus() = %v, want %v", i, got, want)
		}
		if got, want := publicEntry.IsPrimary(), wantPrimary[i]; got != want {
			t.Errorf("publicHandle.Entry(%v).IsPrimary() = %v, want %v", i, got, want)
		}
		privateKey, ok := privateEntry.Key().(*tinked25519.PrivateKey)
		if !ok {
			t.Fatalf("privateEntry.Key() is of type %T, want *tinked25519.PrivateKey", privateEntry.Key())
		}
		publicKey, ok := publicEntry.Key().(*tinked25519.PublicKey)
		if !ok {
			t.Fatalf("publicEntry.Key() is of type %T, want *tinked25519.PublicKey", publicEntry.Key())
		}
		wantPublicKey, err := privateKey.PublicKey()
		if err != nil {
			t.Fatalf("privateKey.PublicKey() err = %v, want nil", err)
		}
		if !publicKey.Equal(wantPublicKey) {
			t.Errorf("publicHandle.Entry(%v).Key() does not match the public key of the private key", i)
		}
		if got, want := publicKey.OutputPrefix(), privateKey.OutputPrefix(); !bytes.Equal(got, want) {
			t.Errorf("publicKey.OutputPrefix() = %v, want %v", got, want)
		}
		if got, want := publicKey.OutputPrefix(), tinkOutputPrefix(wantIDs[i]); !bytes.Equal(got, want) {
			t.Errorf("publicKey.OutputPrefix() = %v, want prefix of key ID %v", got, wantIDs[i])
		}
	}

	publicPrimary, err := publicHandle.Primary()
	if err != nil {
		t.Fatalf("publicHandle.Primary() err = %v, want nil", err)
	}
	if got, want := publicPrimary.KeyID(), rotatedKeyID; got != want {
		t.Errorf("publicHandle.Primary().KeyID() = %v, want %v", got, want)
	}
}

// TestPublicRoutesToActualVerifierPrimitive verifies that the public handle
// of a multi-key asymmetric keyset can be turned into an actual public
// primitive (a [tink.Verifier]), and that signatures produced by the private
// handle are verified through the output prefix of the matching key, both
// before and after a primary key rotation.
func TestPublicRoutesToActualVerifierPrimitive(t *testing.T) {
	privateHandle := mustCreateMultiKeyPrivateHandle(t)

	verifyRoundTrip := func(t *testing.T, private *keyset.Handle, primaryID uint32) {
		t.Helper()
		signer, err := signature.NewSigner(private)
		if err != nil {
			t.Fatalf("signature.NewSigner(private) err = %v, want nil", err)
		}
		publicHandle, err := private.Public()
		if err != nil {
			t.Fatalf("private.Public() err = %v, want nil", err)
		}
		verifier, err := signature.NewVerifier(publicHandle)
		if err != nil {
			t.Fatalf("signature.NewVerifier(publicHandle) err = %v, want nil", err)
		}
		message := []byte("message routed through the public primitive")
		signatureBytes, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("signer.Sign() err = %v, want nil", err)
		}
		if got, want := signatureBytes[:5], tinkOutputPrefix(primaryID); !bytes.Equal(got, want) {
			t.Errorf("signature prefix = %v, want %v", got, want)
		}
		if err := verifier.Verify(signatureBytes, message); err != nil {
			t.Errorf("verifier.Verify() err = %v, want nil", err)
		}
		if err := verifier.Verify(signatureBytes, []byte("other message")); err == nil {
			t.Error("verifier.Verify() with a different message err = nil, want error")
		}
	}

	verifyRoundTrip(t, privateHandle, firstKeyID)
	rotatedPrivateHandle := mustRotatePrimary(t, privateHandle, rotatedKeyID)
	verifyRoundTrip(t, rotatedPrivateHandle, rotatedKeyID)
}

// TestPublicPreservesDisabledEntries verifies that a disabled entry keeps its
// key ID, status and position in the public handle: it is neither re-enabled
// nor renumbered. It also checks that a verifier built from the public handle
// rejects a signature carrying the disabled key's prefix.
func TestPublicPreservesDisabledEntries(t *testing.T) {
	privateHandle := mustCreateMultiKeyPrivateHandle(t)
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}

	disabledIndex := slices.IndexFunc(mustAllEntries(t, publicHandle), func(e *keyset.Entry) bool {
		return e.KeyID() == disabledKeyID
	})
	if disabledIndex < 0 {
		t.Fatalf("disabled key %v not found in public handle", disabledKeyID)
	}
	disabledEntry, err := publicHandle.Entry(disabledIndex)
	if err != nil {
		t.Fatalf("publicHandle.Entry(%v) err = %v, want nil", disabledIndex, err)
	}
	if got, want := disabledEntry.KeyStatus(), keyset.Disabled; got != want {
		t.Errorf("disabledEntry.KeyStatus() = %v, want %v", got, want)
	}
	if disabledEntry.IsPrimary() {
		t.Error("disabledEntry.IsPrimary() = true, want false")
	}
	// The disabled entry keeps its original position; entries are not
	// renumbered during the public export.
	if got, want := disabledIndex, 1; got != want {
		t.Errorf("disabled entry index = %v, want %v", got, want)
	}

	// Re-exporting must not re-enable or renumber the entry.
	publicHandleAgain, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}
	againEntry, err := publicHandleAgain.Entry(disabledIndex)
	if err != nil {
		t.Fatalf("publicHandleAgain.Entry(%v) err = %v, want nil", disabledIndex, err)
	}
	if got, want := againEntry.KeyStatus(), keyset.Disabled; got != want {
		t.Errorf("againEntry.KeyStatus() = %v, want %v", got, want)
	}
	if got, want := againEntry.KeyID(), disabledKeyID; got != want {
		t.Errorf("againEntry.KeyID() = %v, want %v", got, want)
	}

	verifier, err := signature.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(publicHandle) err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	message := []byte("disabled entry must not verify")
	validSignature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(validSignature, message); err != nil {
		t.Errorf("verifier.Verify(validSignature) err = %v, want nil", err)
	}
	// A signature carrying the disabled key's prefix cannot be verified: the
	// verifier built from the public handle has no working route for a
	// signature whose body was not produced by that key.
	forgedSignature := slices.Concat(tinkOutputPrefix(disabledKeyID), validSignature[5:])
	if err := verifier.Verify(forgedSignature, message); err == nil {
		t.Error("verifier.Verify() with a disabled key prefix err = nil, want error")
	}
}

// TestPublicFailsIfAnEntryCannotExportPublicKey verifies that the whole
// public handle conversion fails when a single entry cannot export its public
// key, that no public primitive can be built from the failed result, and that
// the original private handle stays fully usable.
func TestPublicFailsIfAnEntryCannotExportPublicKey(t *testing.T) {
	manager := keyset.NewManager()
	healthyPrivateKey := mustAddEd25519PrivateKey(t, manager, firstKeyID, keyset.Enabled, true)
	mustAddFailingPrivateKey(t, manager, failingKeyID)
	privateHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	publicHandle, err := privateHandle.Public()
	if err == nil {
		t.Fatalf("privateHandle.Public() = %v, want error", publicHandle)
	}
	if publicHandle != nil {
		t.Errorf("privateHandle.Public() returned a non-nil handle: %v", publicHandle)
	}
	// With no public handle, building a public primitive from the result fails.
	if _, err := signature.NewVerifier(publicHandle); err == nil {
		t.Error("signature.NewVerifier(nil handle) err = nil, want error")
	}

	// The original private handle is untouched and still usable.
	if got, want := privateHandle.Len(), 2; got != want {
		t.Fatalf("privateHandle.Len() = %v, want %v", got, want)
	}
	healthyEntry, err := privateHandle.Entry(0)
	if err != nil {
		t.Fatalf("privateHandle.Entry(0) err = %v, want nil", err)
	}
	if got, want := healthyEntry.KeyID(), firstKeyID; got != want {
		t.Errorf("healthyEntry.KeyID() = %v, want %v", got, want)
	}
	if !healthyEntry.IsPrimary() {
		t.Error("healthyEntry.IsPrimary() = false, want true")
	}
	if got := healthyEntry.Key(); !got.Equal(healthyPrivateKey) {
		t.Error("healthyEntry.Key() does not match the original healthy private key")
	}
	failingEntry, err := privateHandle.Entry(1)
	if err != nil {
		t.Fatalf("privateHandle.Entry(1) err = %v, want nil", err)
	}
	if got, want := failingEntry.KeyID(), failingKeyID; got != want {
		t.Errorf("failingEntry.KeyID() = %v, want %v", got, want)
	}
	if _, ok := failingEntry.Key().(*failingPublicKeyPrivateKey); !ok {
		t.Fatalf("failingEntry.Key() is of type %T, want *failingPublicKeyPrivateKey", failingEntry.Key())
	}

	// The primary signer still works, and a second export attempt fails again
	// deterministically.
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	message := []byte("the private handle stays usable after a failed export")
	signatureBytes, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if len(signatureBytes) == 0 {
		t.Error("signer.Sign() returned an empty signature")
	}
	if _, err := privateHandle.Public(); err == nil {
		t.Error("privateHandle.Public() err = nil on second attempt, want error")
	}
}

// TestPublicDoesNotExposePrivateOperationsOrSharedState verifies that the
// public handle only contains public key material, does not expose private
// key operations, and does not share mutable entry state with the private
// handle.
func TestPublicDoesNotExposePrivateOperationsOrSharedState(t *testing.T) {
	privateHandle := mustCreateMultiKeyPrivateHandle(t)
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}

	for i := 0; i < publicHandle.Len(); i++ {
		publicEntry, err := publicHandle.Entry(i)
		if err != nil {
			t.Fatalf("publicHandle.Entry(%v) err = %v, want nil", i, err)
		}
		publicKey, ok := publicEntry.Key().(*tinked25519.PublicKey)
		if !ok {
			t.Fatalf("publicHandle.Entry(%v).Key() is of type %T, want *tinked25519.PublicKey", i, publicEntry.Key())
		}
		// A public key must never implement the private key export interface.
		if _, exposesPrivate := any(publicKey).(interface {
			PublicKey() (key.Key, error)
		}); exposesPrivate {
			t.Errorf("public entry %v exposes a PublicKey() private operation", i)
		}
		if _, exposesPrivateMaterial := any(publicKey).(interface {
			PrivateKeyBytes() secretdata.Bytes
		}); exposesPrivateMaterial {
			t.Errorf("public entry %v exposes private key material", i)
		}
	}

	// The public handle cannot be turned into a signer.
	if _, err := signature.NewSigner(publicHandle); err == nil {
		t.Error("signature.NewSigner(publicHandle) err = nil, want error")
	}
	// A public handle cannot be exported again: its entries are not private keys.
	if _, err := publicHandle.Public(); err == nil {
		t.Error("publicHandle.Public() err = nil, want error")
	}

	// The handles hold distinct entry and key objects.
	privateEntry0, err := privateHandle.Entry(0)
	if err != nil {
		t.Fatalf("privateHandle.Entry(0) err = %v, want nil", err)
	}
	publicEntry0, err := publicHandle.Entry(0)
	if err != nil {
		t.Fatalf("publicHandle.Entry(0) err = %v, want nil", err)
	}
	if privateEntry0 == publicEntry0 {
		t.Error("private and public handles share the same *keyset.Entry object")
	}
	if privateEntry0.Key() == publicEntry0.Key() {
		t.Error("private and public handles share the same key.Key object")
	}

	// Mutating the private handle after the export must not affect the public
	// handle.
	beforeStatuses := make([]keyset.KeyStatus, publicHandle.Len())
	for i := 0; i < publicHandle.Len(); i++ {
		e, err := publicHandle.Entry(i)
		if err != nil {
			t.Fatalf("publicHandle.Entry(%v) err = %v, want nil", i, err)
		}
		beforeStatuses[i] = e.KeyStatus()
	}
	mutatedPrivateHandle := mustRotatePrimary(t, privateHandle, rotatedKeyID)
	manager := keyset.NewManagerFromHandle(mutatedPrivateHandle)
	if err := manager.Disable(firstKeyID); err != nil {
		t.Fatalf("manager.Disable(%v) err = %v, want nil", firstKeyID, err)
	}
	mutatedPrivateHandle, err = manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	mutatedEntry, err := mutatedPrivateHandle.Entry(0)
	if err != nil {
		t.Fatalf("mutatedPrivateHandle.Entry(0) err = %v, want nil", err)
	}
	if got, want := mutatedEntry.KeyStatus(), keyset.Disabled; got != want {
		t.Fatalf("mutatedEntry.KeyStatus() = %v, want %v", got, want)
	}
	for i := 0; i < publicHandle.Len(); i++ {
		e, err := publicHandle.Entry(i)
		if err != nil {
			t.Fatalf("publicHandle.Entry(%v) err = %v, want nil", i, err)
		}
		if e.KeyStatus() != beforeStatuses[i] {
			t.Errorf("publicHandle.Entry(%v).KeyStatus() changed to %v after the private handle was mutated, want %v", i, e.KeyStatus(), beforeStatuses[i])
		}
	}

	// The verifier built from the untouched public handle still verifies a
	// signature made by the original private handle, proving the export did not
	// alias the private key material.
	verifier, err := signature.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(publicHandle) err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	message := []byte("independent state between private and public handles")
	signatureBytes, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(signatureBytes, message); err != nil {
		t.Errorf("verifier.Verify() err = %v, want nil", err)
	}

	// The public handle serializes as a no-secret keyset and round-trips
	// without any private key material.
	buf := &bytes.Buffer{}
	if err := publicHandle.WriteWithNoSecrets(keyset.NewBinaryWriter(buf)); err != nil {
		t.Fatalf("publicHandle.WriteWithNoSecrets() err = %v, want nil", err)
	}
	roundTripped, err := keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(buf.Bytes())))
	if err != nil {
		t.Fatalf("keyset.ReadWithNoSecrets() err = %v, want nil", err)
	}
	if diff := cmp.Diff(publicHandle, roundTripped); diff != "" {
		t.Errorf("public handle round trip diff (-want +got):\n%s", diff)
	}
	for i := 0; i < roundTripped.Len(); i++ {
		e, err := roundTripped.Entry(i)
		if err != nil {
			t.Fatalf("roundTripped.Entry(%v) err = %v, want nil", i, err)
		}
		if _, ok := e.Key().(*tinked25519.PublicKey); !ok {
			t.Errorf("roundTripped.Entry(%v).Key() is of type %T, want *tinked25519.PublicKey", i, e.Key())
		}
	}
}

func mustAllEntries(t *testing.T, h *keyset.Handle) []*keyset.Entry {
	t.Helper()
	entries := make([]*keyset.Entry, h.Len())
	for i := 0; i < h.Len(); i++ {
		e, err := h.Entry(i)
		if err != nil {
			t.Fatalf("h.Entry(%v) err = %v, want nil", i, err)
		}
		entries[i] = e
	}
	return entries
}

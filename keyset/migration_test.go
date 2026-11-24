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
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// failingWriter is a keyset.Writer whose WriteEncrypted always fails. It also
// records whether any write was attempted.
type failingWriter struct {
	writeCalled bool
}

func (w *failingWriter) Write(*tinkpb.Keyset) error {
	return errors.New("failingWriter: cleartext write not supported")
}

func (w *failingWriter) WriteEncrypted(*tinkpb.EncryptedKeyset) error {
	w.writeCalled = true
	return errors.New("failingWriter: write failed")
}

// failingReader is a keyset.Reader whose ReadEncrypted always fails.
type failingReader struct{}

func (r *failingReader) Read() (*tinkpb.Keyset, error) {
	return nil, errors.New("failingReader: read not supported")
}

func (r *failingReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	return nil, errors.New("failingReader: read failed")
}

// recordingWriter stores the last written EncryptedKeyset.
type recordingWriter struct {
	encryptedKeyset *tinkpb.EncryptedKeyset
}

func (w *recordingWriter) Write(*tinkpb.Keyset) error {
	return errors.New("recordingWriter: cleartext write not supported")
}

func (w *recordingWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	w.encryptedKeyset = keyset
	return nil
}

func newTestKeysetEncryptionAEAD(t *testing.T) tink.AEAD {
	t.Helper()
	handle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	kekAEAD, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}
	return kekAEAD
}

func writeEncryptedKeysetForTest(t *testing.T, handle *keyset.Handle, kekAEAD tink.AEAD, associatedData []byte) []byte {
	t.Helper()
	buff := &bytes.Buffer{}
	if err := handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), kekAEAD, associatedData); err != nil {
		t.Fatalf("handle.WriteWithAssociatedData() err = %v, want nil", err)
	}
	return buff.Bytes()
}

func mustNewHandle(t *testing.T) *keyset.Handle {
	t.Helper()
	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	return handle
}

func TestMigrate(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)
	oldAssociatedData := []byte("old context")
	newAssociatedData := []byte("new context")

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, oldAssociatedData)

	writer := &recordingWriter{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		oldKEK, oldAssociatedData,
		newKEK, newAssociatedData,
	)
	if err != nil {
		t.Fatalf("keyset.Migrate() err = %v, want nil", err)
	}
	if migratedHandle == nil {
		t.Fatal("keyset.Migrate() returned nil handle, want non-nil")
	}
	if writer.encryptedKeyset == nil {
		t.Fatal("keyset.Migrate() did not write the migrated keyset")
	}

	// The migrated keyset keeps the same key identities, primary key and
	// content.
	if !migratedHandle.Equal(handle) {
		t.Errorf("migratedHandle.Equal(handle) = false, want true")
	}
	if got, want := migratedHandle.KeysetInfo(), handle.KeysetInfo(); !proto.Equal(got, want) {
		t.Errorf("migratedHandle.KeysetInfo() = %v, want %v", got, want)
	}
	if got, want := testkeyset.KeysetMaterial(migratedHandle), testkeyset.KeysetMaterial(handle); !proto.Equal(got, want) {
		t.Errorf("migrated keyset material = %v, want %v", got, want)
	}

	// The migrated keyset is readable under the new combination.
	migratedBytes := &bytes.Buffer{}
	if err := keyset.NewBinaryWriter(migratedBytes).WriteEncrypted(writer.encryptedKeyset); err != nil {
		t.Fatalf("WriteEncrypted() err = %v, want nil", err)
	}
	readBack, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(migratedBytes), newKEK, newAssociatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() with new context err = %v, want nil", err)
	}
	if !readBack.Equal(handle) {
		t.Errorf("readBack.Equal(handle) = false, want true")
	}

	// The new storage cannot be opened with the old key or old context.
	if _, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(migratedBytes.Bytes())), oldKEK, oldAssociatedData); err == nil {
		t.Error("ReadWithAssociatedData() with old KEK err = nil, want err")
	}
	if _, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(migratedBytes.Bytes())), newKEK, oldAssociatedData); err == nil {
		t.Error("ReadWithAssociatedData() with old associated data err = nil, want err")
	}
	if _, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(migratedBytes.Bytes())), oldKEK, newAssociatedData); err == nil {
		t.Error("ReadWithAssociatedData() with old KEK and new associated data err = nil, want err")
	}

	// The original, pre-migration encrypted keyset remains readable.
	originalReadBack, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), oldKEK, oldAssociatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() on original keyset err = %v, want nil", err)
	}
	if !originalReadBack.Equal(handle) {
		t.Errorf("originalReadBack.Equal(handle) = false, want true")
	}
}

func TestMigratePreservesMultipleKeysAndPrimary(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)

	// Build a keyset with multiple keys and a non-first primary key.
	manager := keyset.NewManager()
	firstID, err := manager.Add(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add() err = %v, want nil", err)
	}
	secondID, err := manager.Add(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add() err = %v, want nil", err)
	}
	if err := manager.SetPrimary(secondID); err != nil {
		t.Fatalf("manager.SetPrimary(%d) err = %v, want nil", secondID, err)
	}
	if err := manager.Disable(firstID); err != nil {
		t.Fatalf("manager.Disable(%d) err = %v, want nil", firstID, err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, []byte("old context"))
	writer := &recordingWriter{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		oldKEK, []byte("old context"),
		newKEK, []byte("new context"),
	)
	if err != nil {
		t.Fatalf("keyset.Migrate() err = %v, want nil", err)
	}
	if !migratedHandle.Equal(handle) {
		t.Errorf("migratedHandle.Equal(handle) = false, want true")
	}
	primary, err := migratedHandle.Primary()
	if err != nil {
		t.Fatalf("migratedHandle.Primary() err = %v, want nil", err)
	}
	if primary.KeyID() != secondID {
		t.Errorf("primary.KeyID() = %d, want %d", primary.KeyID(), secondID)
	}
	if migratedHandle.Len() != handle.Len() {
		t.Errorf("migratedHandle.Len() = %d, want %d", migratedHandle.Len(), handle.Len())
	}
}

func TestMigrateFailsWithWrongOldContext(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)
	oldAssociatedData := []byte("old context")

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, oldAssociatedData)

	writer := &failingWriter{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		oldKEK, []byte("wrong context"),
		newKEK, []byte("new context"),
	)
	if err == nil {
		t.Fatal("keyset.Migrate() with wrong old associated data err = nil, want err")
	}
	if migratedHandle != nil {
		t.Errorf("keyset.Migrate() returned non-nil handle on failure, want nil")
	}
	if writer.writeCalled {
		t.Error("writer.WriteEncrypted was called despite decryption failure")
	}

	// The original keyset is still readable.
	readBack, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), oldKEK, oldAssociatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() on original keyset err = %v, want nil", err)
	}
	if !readBack.Equal(handle) {
		t.Errorf("readBack.Equal(handle) = false, want true")
	}
}

func TestMigrateFailsWithWrongOldKey(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	otherKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, []byte("old context"))

	writer := &failingWriter{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		otherKEK, []byte("old context"),
		newKEK, []byte("new context"),
	)
	if err == nil {
		t.Fatal("keyset.Migrate() with wrong old KEK err = nil, want err")
	}
	if migratedHandle != nil {
		t.Errorf("keyset.Migrate() returned non-nil handle on failure, want nil")
	}
	if writer.writeCalled {
		t.Error("writer.WriteEncrypted was called despite decryption failure")
	}
}

func TestMigrateFailsWhenWriteFails(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)
	oldAssociatedData := []byte("old context")
	newAssociatedData := []byte("new context")

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, oldAssociatedData)

	writer := &failingWriter{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		oldKEK, oldAssociatedData,
		newKEK, newAssociatedData,
	)
	if err == nil {
		t.Fatal("keyset.Migrate() with failing writer err = nil, want err")
	}
	if migratedHandle != nil {
		t.Errorf("keyset.Migrate() returned non-nil handle on write failure, want nil")
	}

	// No half-migrated result is delivered: the original keyset remains
	// readable under the old combination.
	readBack, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), oldKEK, oldAssociatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() on original keyset err = %v, want nil", err)
	}
	if !readBack.Equal(handle) {
		t.Errorf("readBack.Equal(handle) = false, want true")
	}
}

func TestMigrateFailsWithNilArguments(t *testing.T) {
	kek := newTestKeysetEncryptionAEAD(t)
	encrypted := writeEncryptedKeysetForTest(t, mustNewHandle(t), kek, []byte("old context"))
	reader := keyset.NewBinaryReader(bytes.NewBuffer(encrypted))
	writer := &recordingWriter{}

	testCases := []struct {
		name    string
		reader  keyset.Reader
		writer  keyset.Writer
		oldAEAD tink.AEAD
		newAEAD tink.AEAD
	}{
		{name: "nil reader", reader: nil, writer: writer, oldAEAD: kek, newAEAD: kek},
		{name: "nil writer", reader: reader, writer: nil, oldAEAD: kek, newAEAD: kek},
		{name: "nil old AEAD", reader: reader, writer: writer, oldAEAD: nil, newAEAD: kek},
		{name: "nil new AEAD", reader: reader, writer: writer, oldAEAD: kek, newAEAD: nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handle, err := keyset.Migrate(tc.reader, tc.writer, tc.oldAEAD, []byte("old context"), tc.newAEAD, []byte("new context"))
			if err == nil {
				t.Fatal("keyset.Migrate() err = nil, want err")
			}
			if handle != nil {
				t.Errorf("keyset.Migrate() returned non-nil handle, want nil")
			}
		})
	}
}

func TestMigrateWithContext(t *testing.T) {
	oldKEK, err := fakekms.NewAEADWithContext(fakeKeyURI)
	if err != nil {
		t.Fatalf("fakekms.NewAEADWithContext(fakeKeyURI) err = %v, want nil", err)
	}
	newKeyURI, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatalf("fakekms.NewKeyURI() err = %v, want nil", err)
	}
	newKEK, err := fakekms.NewAEADWithContext(newKeyURI)
	if err != nil {
		t.Fatalf("fakekms.NewAEADWithContext(newKeyURI) err = %v, want nil", err)
	}
	oldAssociatedData := []byte("old context")
	newAssociatedData := []byte("new context")

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	ctx := context.Background()
	buff := &bytes.Buffer{}
	if err := handle.WriteWithContext(ctx, keyset.NewBinaryWriter(buff), oldKEK, oldAssociatedData); err != nil {
		t.Fatalf("handle.WriteWithContext() err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	writer := &recordingWriter{}
	migratedHandle, err := keyset.MigrateWithContext(
		ctx,
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		oldKEK, oldAssociatedData,
		newKEK, newAssociatedData,
	)
	if err != nil {
		t.Fatalf("keyset.MigrateWithContext() err = %v, want nil", err)
	}
	if !migratedHandle.Equal(handle) {
		t.Errorf("migratedHandle.Equal(handle) = false, want true")
	}

	migratedBytes := &bytes.Buffer{}
	if err := keyset.NewBinaryWriter(migratedBytes).WriteEncrypted(writer.encryptedKeyset); err != nil {
		t.Fatalf("WriteEncrypted() err = %v, want nil", err)
	}
	readBack, err := keyset.ReadWithContext(ctx, keyset.NewBinaryReader(migratedBytes), newKEK, newAssociatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithContext() with new context err = %v, want nil", err)
	}
	if !readBack.Equal(handle) {
		t.Errorf("readBack.Equal(handle) = false, want true")
	}

	// The migrated keyset cannot be opened with the old combination.
	if _, err := keyset.ReadWithContext(ctx, keyset.NewBinaryReader(bytes.NewBuffer(migratedBytes.Bytes())), oldKEK, oldAssociatedData); err == nil {
		t.Error("ReadWithContext() with old KEK err = nil, want err")
	}
	// The original keyset remains readable.
	if _, err := keyset.ReadWithContext(ctx, keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), oldKEK, oldAssociatedData); err != nil {
		t.Errorf("ReadWithContext() on original keyset err = %v, want nil", err)
	}
}

func TestMigrateWithContextDoesNotIgnoreContext(t *testing.T) {
	oldKEK, err := fakekms.NewAEADWithContext(fakeKeyURI)
	if err != nil {
		t.Fatalf("fakekms.NewAEADWithContext(fakeKeyURI) err = %v, want nil", err)
	}
	newKEK, err := fakekms.NewAEADWithContext(fakeKeyURI)
	if err != nil {
		t.Fatalf("fakekms.NewAEADWithContext(fakeKeyURI) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	ctx := context.Background()
	buff := &bytes.Buffer{}
	if err := handle.WriteWithContext(ctx, keyset.NewBinaryWriter(buff), oldKEK, []byte("old context")); err != nil {
		t.Fatalf("handle.WriteWithContext() err = %v, want nil", err)
	}

	canceledCtx, cancel := context.WithCancelCause(ctx)
	causeErr := errors.New("cause error message")
	cancel(causeErr)

	writer := &recordingWriter{}
	migratedHandle, err := keyset.MigrateWithContext(
		canceledCtx,
		keyset.NewBinaryReader(buff),
		writer,
		oldKEK, []byte("old context"),
		newKEK, []byte("new context"),
	)
	if err == nil {
		t.Fatal("keyset.MigrateWithContext() with canceled context err = nil, want err")
	}
	if migratedHandle != nil {
		t.Errorf("keyset.MigrateWithContext() returned non-nil handle, want nil")
	}
	if writer.encryptedKeyset != nil {
		t.Error("writer was modified despite context cancellation")
	}
}

func TestMigrateWithContextFailsWithNilArguments(t *testing.T) {
	kek, err := fakekms.NewAEADWithContext(fakeKeyURI)
	if err != nil {
		t.Fatalf("fakekms.NewAEADWithContext(fakeKeyURI) err = %v, want nil", err)
	}
	ctx := context.Background()
	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := handle.WriteWithContext(ctx, keyset.NewBinaryWriter(buff), kek, []byte("old context")); err != nil {
		t.Fatalf("handle.WriteWithContext() err = %v, want nil", err)
	}
	reader := keyset.NewBinaryReader(buff)
	writer := &recordingWriter{}

	testCases := []struct {
		name    string
		reader  keyset.Reader
		writer  keyset.Writer
		oldAEAD tink.AEADWithContext
		newAEAD tink.AEADWithContext
	}{
		{name: "nil reader", reader: nil, writer: writer, oldAEAD: kek, newAEAD: kek},
		{name: "nil writer", reader: reader, writer: nil, oldAEAD: kek, newAEAD: kek},
		{name: "nil old AEAD", reader: reader, writer: writer, oldAEAD: nil, newAEAD: kek},
		{name: "nil new AEAD", reader: reader, writer: writer, oldAEAD: kek, newAEAD: nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			migratedHandle, err := keyset.MigrateWithContext(
				ctx, tc.reader, tc.writer,
				tc.oldAEAD, []byte("old context"),
				tc.newAEAD, []byte("new context"),
			)
			if err == nil {
				t.Fatal("keyset.MigrateWithContext() err = nil, want err")
			}
			if migratedHandle != nil {
				t.Errorf("keyset.MigrateWithContext() returned non-nil handle, want nil")
			}
		})
	}
}

func TestMigrateFailsWhenReadFails(t *testing.T) {
	newKEK := newTestKeysetEncryptionAEAD(t)
	writer := &recordingWriter{}
	migratedHandle, err := keyset.Migrate(
		&failingReader{},
		writer,
		newTestKeysetEncryptionAEAD(t), []byte("old context"),
		newKEK, []byte("new context"),
	)
	if err == nil {
		t.Fatal("keyset.Migrate() with failing reader err = nil, want err")
	}
	if migratedHandle != nil {
		t.Errorf("keyset.Migrate() returned non-nil handle, want nil")
	}
	if writer.encryptedKeyset != nil {
		t.Error("writer was modified despite read failure")
	}
}

func TestMigrateInPlaceOverwrite(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)
	oldAssociatedData := []byte("old context")
	newAssociatedData := []byte("new context")

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, oldAssociatedData)

	// Use one in-memory storage as both the old and the new location, like an
	// application rotating the master key of its on-disk keyset in place.
	storage := &keyset.MemReaderWriter{
		EncryptedKeyset: mustParseEncryptedKeyset(t, encrypted),
	}
	migratedHandle, err := keyset.Migrate(storage, storage, oldKEK, oldAssociatedData, newKEK, newAssociatedData)
	if err != nil {
		t.Fatalf("keyset.Migrate() err = %v, want nil", err)
	}
	if !migratedHandle.Equal(handle) {
		t.Errorf("migratedHandle.Equal(handle) = false, want true")
	}

	// The storage now only opens with the new combination.
	if _, err := keyset.ReadWithAssociatedData(storage, newKEK, newAssociatedData); err != nil {
		t.Errorf("keyset.ReadWithAssociatedData() with new context err = %v, want nil", err)
	}
	if _, err := keyset.ReadWithAssociatedData(storage, oldKEK, oldAssociatedData); err == nil {
		t.Error("keyset.ReadWithAssociatedData() with old context err = nil, want err")
	}
}

func TestMigrateAcrossStorageFormats(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)
	oldAssociatedData := []byte("old context")
	newAssociatedData := []byte("new context")

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	encrypted := writeEncryptedKeysetForTest(t, handle, oldKEK, oldAssociatedData)

	// Read from binary storage and write to JSON storage.
	jsonBuff := &bytes.Buffer{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		keyset.NewJSONWriter(jsonBuff),
		oldKEK, oldAssociatedData,
		newKEK, newAssociatedData,
	)
	if err != nil {
		t.Fatalf("keyset.Migrate() err = %v, want nil", err)
	}
	if !migratedHandle.Equal(handle) {
		t.Errorf("migratedHandle.Equal(handle) = false, want true")
	}

	readBack, err := keyset.ReadWithAssociatedData(keyset.NewJSONReader(jsonBuff), newKEK, newAssociatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() from JSON storage err = %v, want nil", err)
	}
	if !readBack.Equal(handle) {
		t.Errorf("readBack.Equal(handle) = false, want true")
	}
	if _, err := keyset.ReadWithAssociatedData(keyset.NewJSONReader(bytes.NewBuffer(jsonBuff.Bytes())), oldKEK, oldAssociatedData); err == nil {
		t.Error("ReadWithAssociatedData() with old context on JSON storage err = nil, want err")
	}
}

func mustParseEncryptedKeyset(t *testing.T, serialized []byte) *tinkpb.EncryptedKeyset {
	t.Helper()
	encryptedKeyset, err := keyset.NewBinaryReader(bytes.NewBuffer(serialized)).ReadEncrypted()
	if err != nil {
		t.Fatalf("ReadEncrypted() err = %v, want nil", err)
	}
	return encryptedKeyset
}

func TestMigrateWithEmptyAssociatedData(t *testing.T) {
	oldKEK := newTestKeysetEncryptionAEAD(t)
	newKEK := newTestKeysetEncryptionAEAD(t)

	handle, err := keyset.NewHandle(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(keytest.TinkLegacyKeyTemplate()) err = %v, want nil", err)
	}
	// Write using Handle.Write, which uses empty associated data.
	buff := &bytes.Buffer{}
	if err := handle.Write(keyset.NewBinaryWriter(buff), oldKEK); err != nil {
		t.Fatalf("handle.Write() err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	writer := &recordingWriter{}
	migratedHandle, err := keyset.Migrate(
		keyset.NewBinaryReader(bytes.NewBuffer(encrypted)),
		writer,
		oldKEK, nil,
		newKEK, nil,
	)
	if err != nil {
		t.Fatalf("keyset.Migrate() err = %v, want nil", err)
	}
	if !migratedHandle.Equal(handle) {
		t.Errorf("migratedHandle.Equal(handle) = false, want true")
	}

	migratedBytes := &bytes.Buffer{}
	if err := keyset.NewBinaryWriter(migratedBytes).WriteEncrypted(writer.encryptedKeyset); err != nil {
		t.Fatalf("WriteEncrypted() err = %v, want nil", err)
	}
	// Read via keyset.Read, which uses empty associated data.
	readBack, err := keyset.Read(keyset.NewBinaryReader(migratedBytes), newKEK)
	if err != nil {
		t.Fatalf("keyset.Read() with new KEK err = %v, want nil", err)
	}
	if !readBack.Equal(handle) {
		t.Errorf("readBack.Equal(handle) = false, want true")
	}
	if _, err := keyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(migratedBytes.Bytes())), oldKEK); err == nil {
		t.Error("keyset.Read() with old KEK err = nil, want err")
	}
}

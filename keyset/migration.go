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

package keyset

import (
	"context"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// Migrate decrypts an encrypted keyset read from reader with
// oldKeyEncryptionAEAD and oldAssociatedData, re-encrypts it with
// newKeyEncryptionAEAD and newAssociatedData, and writes the result to writer.
//
// The plaintext key material never leaves the keyset package and is never
// exposed to the caller. Key identities, key statuses, the primary key
// relationship and all other keyset content are preserved. A keyset
// re-encrypted under the new key encryption AEAD and associated data cannot be
// decrypted with the old key encryption AEAD or old associated data.
//
// The migration does not deliver a half-migrated result. The keyset is fully
// decrypted under the old combination and re-encrypted under the new
// combination before writer is invoked: if the old key encryption AEAD or old
// associated data cannot decrypt the keyset, or if re-encryption fails,
// writer is never invoked and an error is returned. If writer.WriteEncrypted
// fails, the error is propagated and no migrated handle is returned, so the
// caller cannot mistake a failed migration for a successful one. Keysets
// stored elsewhere remain readable through [Read] and
// [ReadWithAssociatedData].
//
// The returned [Handle] represents the migrated keyset and can be used without
// reading it back from writer.
func Migrate(reader Reader, writer Writer, oldKeyEncryptionAEAD tink.AEAD, oldAssociatedData []byte, newKeyEncryptionAEAD tink.AEAD, newAssociatedData []byte) (*Handle, error) {
	if reader == nil || writer == nil || oldKeyEncryptionAEAD == nil || newKeyEncryptionAEAD == nil {
		return nil, fmt.Errorf("keyset.Migrate: reader, writer and both key encryption AEADs must be non-nil")
	}
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	protoKeyset, err := decrypt(encryptedKeyset, oldKeyEncryptionAEAD, oldAssociatedData)
	if err != nil {
		return nil, err
	}
	reEncrypted, err := encrypt(protoKeyset, newKeyEncryptionAEAD, newAssociatedData)
	if err != nil {
		return nil, err
	}
	if err := writer.WriteEncrypted(reEncrypted); err != nil {
		return nil, err
	}
	return newKeysetHandleFromProto(protoKeyset)
}

// MigrateWithContext does the same as [Migrate], but uses
// [tink.AEADWithContext] instances and the given context.
func MigrateWithContext(ctx context.Context, reader Reader, writer Writer, oldKeyEncryptionAEAD tink.AEADWithContext, oldAssociatedData []byte, newKeyEncryptionAEAD tink.AEADWithContext, newAssociatedData []byte) (*Handle, error) {
	if reader == nil || writer == nil || oldKeyEncryptionAEAD == nil || newKeyEncryptionAEAD == nil {
		return nil, fmt.Errorf("keyset.MigrateWithContext: reader, writer and both key encryption AEADs must be non-nil")
	}
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	protoKeyset, err := decryptWithContext(ctx, encryptedKeyset, oldKeyEncryptionAEAD, oldAssociatedData)
	if err != nil {
		return nil, err
	}
	reEncrypted, err := encryptWithContext(ctx, protoKeyset, newKeyEncryptionAEAD, newAssociatedData)
	if err != nil {
		return nil, err
	}
	if err := writer.WriteEncrypted(reEncrypted); err != nil {
		return nil, err
	}
	return newKeysetHandleFromProto(protoKeyset)
}

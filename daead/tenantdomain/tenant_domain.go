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

// Package tenantdomain provides deterministic encryption with domain
// separation for multi-tenant data fields.
//
// In a multi-tenant system, deterministic ciphertexts enable equality
// queries (e.g. deduplication, joins, lookups) on encrypted columns.
// Without isolation, however, the same plaintext encrypted for different
// tenants — or for different fields of the same tenant — yields the same
// ciphertext, allowing cross-tenant and cross-field correlation.
//
// This package binds every ciphertext to an encryption [Domain] composed
// of a tenant identity and a field identity. The domain is encoded
// unambiguously and authenticated as associated data of the underlying
// [tink.DeterministicAEAD], so:
//
//   - within one domain, equal plaintexts still yield equal ciphertexts
//     (equality queries keep working);
//   - across domains, equal plaintexts yield different ciphertexts, and a
//     ciphertext produced in one domain cannot be decrypted in another
//     (no cross-tenant correlation, no interchangeable ciphertexts).
//
// Key rotation is unaffected: the wrapped primitive is typically obtained
// from [daead.New] on a keyset handle, and rotation of the underlying
// keyset works exactly as before — ciphertexts encrypted before a
// rotation remain decryptable in their original domain.
package tenantdomain

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// ErrDomainMismatch is returned (wrapped) by [Cipher.Decrypt] when a
// ciphertext cannot be authenticated in the requested domain — for
// example because it was encrypted for a different tenant or field, or
// because it was corrupted. Callers can test for it with
// [errors.Is]:
//
//	pt, err := cipher.Decrypt(ct, domain)
//	if errors.Is(err, tenantdomain.ErrDomainMismatch) {
//		// ciphertext does not belong to this tenant/field
//	}
var ErrDomainMismatch = errors.New("tenantdomain: ciphertext does not belong to the requested domain")

// domainEncodingVersion tags the domain encoding so that the scheme can
// evolve without ambiguity with previously emitted ciphertexts.
const domainEncodingVersion = "TDF1"

// maxComponentLen bounds tenant and field identifiers so that their
// lengths always fit the 4-byte length prefix.
const maxComponentLen = 1<<32 - 1

// Domain is an encryption domain: the combination of a tenant identity
// and a field identity within that tenant.
//
// A Domain must be constructed with [NewDomain]; the zero value is not
// valid.
type Domain struct {
	tenantID string
	field    string
}

// NewDomain returns the encryption domain for the given tenant and field
// identities. Both must be non-empty.
func NewDomain(tenantID, field string) (Domain, error) {
	if tenantID == "" {
		return Domain{}, errors.New("tenantdomain.NewDomain: tenant ID must not be empty")
	}
	if field == "" {
		return Domain{}, errors.New("tenantdomain.NewDomain: field must not be empty")
	}
	if len(tenantID) > maxComponentLen || len(field) > maxComponentLen {
		return Domain{}, errors.New("tenantdomain.NewDomain: tenant ID and field must each be at most 2^32-1 bytes")
	}
	return Domain{tenantID: tenantID, field: field}, nil
}

// TenantID returns the tenant identity of the domain.
func (d Domain) TenantID() string { return d.tenantID }

// Field returns the field identity of the domain.
func (d Domain) Field() string { return d.field }

// associatedData encodes the domain as associated authenticated data.
//
// The encoding is a version tag followed by length-prefixed components:
//
//	"TDF1" || uint32be(len(tenantID)) || tenantID || uint32be(len(field)) || field
//
// Length-prefixing makes the composition injective: distinct
// (tenantID, field) pairs never map to the same encoding, so no pair of
// domains can produce interchangeable ciphertexts (e.g. ("ab", "c") and
// ("a", "bc") encode differently).
func (d Domain) associatedData() []byte {
	aad := make([]byte, 0, len(domainEncodingVersion)+4+len(d.tenantID)+4+len(d.field))
	aad = append(aad, domainEncodingVersion...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(d.tenantID)))
	aad = append(aad, d.tenantID...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(d.field)))
	aad = append(aad, d.field...)
	return aad
}

// Cipher deterministically encrypts data fields with domain separation.
//
// It wraps a [tink.DeterministicAEAD] — typically one created with
// [daead.New] from a keyset handle — and binds each ciphertext to a
// [Domain]. Key rotation of the underlying keyset keeps working: old
// ciphertexts remain decryptable in their original domain after a new
// primary key is added.
type Cipher struct {
	base tink.DeterministicAEAD
}

// New returns a Cipher that performs domain-separated deterministic
// encryption using base as the underlying primitive.
func New(base tink.DeterministicAEAD) (*Cipher, error) {
	if base == nil {
		return nil, errors.New("tenantdomain.New: base deterministic AEAD must not be nil")
	}
	return &Cipher{base: base}, nil
}

// Encrypt deterministically encrypts plaintext in the given domain.
//
// Equal (domain, plaintext) pairs always yield equal ciphertexts, so
// equality queries within a domain keep working. Equal plaintexts in
// different domains yield different, non-interchangeable ciphertexts.
func (c *Cipher) Encrypt(plaintext []byte, domain Domain) ([]byte, error) {
	if err := domain.valid(); err != nil {
		return nil, err
	}
	return c.base.EncryptDeterministically(plaintext, domain.associatedData())
}

// Decrypt decrypts ciphertext in the given domain.
//
// If the ciphertext was not produced by [Cipher.Encrypt] for exactly this
// domain (tenant and field), Decrypt returns an error wrapping
// [ErrDomainMismatch], which callers can detect with [errors.Is].
func (c *Cipher) Decrypt(ciphertext []byte, domain Domain) ([]byte, error) {
	if err := domain.valid(); err != nil {
		return nil, err
	}
	pt, err := c.base.DecryptDeterministically(ciphertext, domain.associatedData())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDomainMismatch, err)
	}
	return pt, nil
}

func (d Domain) valid() error {
	if d.tenantID == "" || d.field == "" {
		return errors.New("tenantdomain: invalid domain, use NewDomain to construct it")
	}
	return nil
}

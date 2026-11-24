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

package tenantdomain_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/daead/tenantdomain"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func mustDomain(t *testing.T, tenantID, field string) tenantdomain.Domain {
	t.Helper()
	d, err := tenantdomain.NewDomain(tenantID, field)
	if err != nil {
		t.Fatalf("tenantdomain.NewDomain(%q, %q) err = %v, want nil", tenantID, field, err)
	}
	return d
}

func mustNewKeysetHandle(t *testing.T) (*keyset.Manager, *keyset.Handle) {
	t.Helper()
	params, err := aessiv.NewParameters(64, aessiv.VariantTink)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	return km, handle
}

func mustNewCipher(t *testing.T, handle *keyset.Handle) *tenantdomain.Cipher {
	t.Helper()
	base, err := daead.New(handle)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	c, err := tenantdomain.New(base)
	if err != nil {
		t.Fatalf("tenantdomain.New() err = %v, want nil", err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	domain := mustDomain(t, "tenant-1", "email")
	plaintext := []byte("alice@example.com")

	ct, err := c.Encrypt(plaintext, domain)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	pt, err := c.Decrypt(ct, domain)
	if err != nil {
		t.Fatalf("c.Decrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("c.Decrypt(c.Encrypt(%q)) = %q, want %q", plaintext, pt, plaintext)
	}
}

func TestEncryptIsDeterministicWithinDomain(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	domain := mustDomain(t, "tenant-1", "email")
	plaintext := []byte("alice@example.com")

	ct1, err := c.Encrypt(plaintext, domain)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	ct2, err := c.Encrypt(plaintext, domain)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Errorf("same plaintext in same domain gave different ciphertexts: %x vs %x", ct1, ct2)
	}
}

func TestDifferentDomainsYieldDifferentCiphertexts(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	plaintext := []byte("alice@example.com")
	reference := mustDomain(t, "tenant-1", "email")
	otherDomains := []tenantdomain.Domain{
		mustDomain(t, "tenant-2", "email"),  // different tenant
		mustDomain(t, "tenant-1", "phone"),  // different field
		mustDomain(t, "tenant-10", "email"), // tenant ID that is a superstring
	}

	refCT, err := c.Encrypt(plaintext, reference)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	for _, other := range otherDomains {
		ct, err := c.Encrypt(plaintext, other)
		if err != nil {
			t.Fatalf("c.Encrypt() err = %v, want nil", err)
		}
		if bytes.Equal(ct, refCT) {
			t.Errorf("domains %q/%q and %q/%q produced the same ciphertext for the same plaintext",
				reference.TenantID(), reference.Field(), other.TenantID(), other.Field())
		}
	}
}

func TestCiphertextsAreNotInterchangeableAcrossDomains(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	domainA := mustDomain(t, "tenant-1", "email")
	domainB := mustDomain(t, "tenant-2", "email")

	ct, err := c.Encrypt([]byte("alice@example.com"), domainA)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	if _, err := c.Decrypt(ct, domainB); !errors.Is(err, tenantdomain.ErrDomainMismatch) {
		t.Errorf("c.Decrypt() with a foreign domain err = %v, want errors.Is(err, tenantdomain.ErrDomainMismatch)", err)
	}
}

func TestDomainCompositionIsUnambiguous(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	plaintext := []byte("same plaintext")
	// Component boundaries must be unambiguous: ("ab", "c") and ("a", "bc")
	// concatenate to the same string but are different domains.
	domain1 := mustDomain(t, "ab", "c")
	domain2 := mustDomain(t, "a", "bc")

	ct1, err := c.Encrypt(plaintext, domain1)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	ct2, err := c.Encrypt(plaintext, domain2)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Errorf("ambiguous domain composition: (\"ab\", \"c\") and (\"a\", \"bc\") produced the same ciphertext")
	}
	if _, err := c.Decrypt(ct1, domain2); !errors.Is(err, tenantdomain.ErrDomainMismatch) {
		t.Errorf("c.Decrypt() across ambiguous-looking domains err = %v, want ErrDomainMismatch", err)
	}
}

func TestDecryptWithCorruptedCiphertextReturnsDomainMismatch(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	domain := mustDomain(t, "tenant-1", "email")

	ct, err := c.Encrypt([]byte("alice@example.com"), domain)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := c.Decrypt(ct, domain); !errors.Is(err, tenantdomain.ErrDomainMismatch) {
		t.Errorf("c.Decrypt() with corrupted ciphertext err = %v, want errors.Is(err, tenantdomain.ErrDomainMismatch)", err)
	}
}

func TestKeyRotationKeepsOldCiphertextsDecryptable(t *testing.T) {
	km, handle := mustNewKeysetHandle(t)
	domain := mustDomain(t, "tenant-1", "email")
	plaintext := []byte("alice@example.com")

	cBefore, err := tenantdomain.New(mustDAEAD(t, handle))
	if err != nil {
		t.Fatalf("tenantdomain.New() err = %v, want nil", err)
	}
	ctBefore, err := cBefore.Encrypt(plaintext, domain)
	if err != nil {
		t.Fatalf("c.Encrypt() err = %v, want nil", err)
	}

	// Rotate: add a new key and make it primary.
	params, err := aessiv.NewParameters(64, aessiv.VariantTink)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	newKeyID, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := km.SetPrimary(newKeyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	rotatedHandle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	cAfter := mustNewCipher(t, rotatedHandle)

	// Ciphertexts encrypted before rotation still decrypt in their domain.
	pt, err := cAfter.Decrypt(ctBefore, domain)
	if err != nil {
		t.Fatalf("c.Decrypt() of pre-rotation ciphertext err = %v, want nil", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("decrypted pre-rotation ciphertext = %q, want %q", pt, plaintext)
	}

	// New ciphertexts use the new primary key and round-trip as well.
	ctAfter, err := cAfter.Encrypt(plaintext, domain)
	if err != nil {
		t.Fatalf("c.Encrypt() after rotation err = %v, want nil", err)
	}
	if bytes.Equal(ctAfter, ctBefore) {
		t.Errorf("ciphertext did not change after key rotation")
	}
	if _, err := cAfter.Decrypt(ctAfter, domain); err != nil {
		t.Fatalf("c.Decrypt() of post-rotation ciphertext err = %v, want nil", err)
	}

	// Rotation does not weaken domain isolation.
	if _, err := cAfter.Decrypt(ctBefore, mustDomain(t, "tenant-2", "email")); !errors.Is(err, tenantdomain.ErrDomainMismatch) {
		t.Errorf("c.Decrypt() of pre-rotation ciphertext in foreign domain err = %v, want ErrDomainMismatch", err)
	}
}

func mustDAEAD(t *testing.T, handle *keyset.Handle) tink.DeterministicAEAD {
	t.Helper()
	d, err := daead.New(handle)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	return d
}

func TestNewDomainRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		tenantID string
		field    string
	}{
		{"", "email"},
		{"tenant-1", ""},
		{"", ""},
	} {
		if _, err := tenantdomain.NewDomain(tc.tenantID, tc.field); err == nil {
			t.Errorf("tenantdomain.NewDomain(%q, %q) err = nil, want non-nil", tc.tenantID, tc.field)
		}
	}
}

func TestZeroValueDomainIsRejected(t *testing.T) {
	_, handle := mustNewKeysetHandle(t)
	c := mustNewCipher(t, handle)
	var zero tenantdomain.Domain
	if _, err := c.Encrypt([]byte("data"), zero); err == nil {
		t.Errorf("c.Encrypt() with zero-value Domain err = nil, want non-nil")
	}
	if _, err := c.Decrypt([]byte("ciphertext"), zero); err == nil {
		t.Errorf("c.Decrypt() with zero-value Domain err = nil, want non-nil")
	}
}

func TestNewRejectsNilBase(t *testing.T) {
	if _, err := tenantdomain.New(nil); err == nil {
		t.Errorf("tenantdomain.New(nil) err = nil, want non-nil")
	}
}

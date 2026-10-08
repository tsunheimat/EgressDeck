package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testKey(value byte) []byte { return bytes.Repeat([]byte{value}, KeySize) }

func testVault(t *testing.T) *Vault {
	t.Helper()
	v, err := New("application-2026", testKey(0x42))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRoundTripPersistenceContainsNoPlaintext(t *testing.T) {
	v := testVault(t)
	secret := []byte("https://subscription.example/private?token=very-sensitive-credential")
	envelope, err := v.Seal("provider/123/source", secret)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"subscription.example", "very-sensitive-credential", string(secret), string(testKey(0x42)), base64.StdEncoding.EncodeToString(testKey(0x42))} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("persisted envelope contains sensitive material")
		}
	}
	var restored Envelope
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	// Rebuild the vault to demonstrate independent recovery from external keys.
	reopened := testVault(t)
	got, err := reopened.Open("provider/123/source", restored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("reopened secret differs")
	}
	second, err := v.Seal("provider/123/source", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(envelope.Nonce, second.Nonce) || bytes.Equal(envelope.Ciphertext, second.Ciphertext) {
		t.Fatal("repeated encryption reused nonce or ciphertext")
	}
}

func TestEnvelopeRejectsTamperingAndObjectSubstitution(t *testing.T) {
	v := testVault(t)
	envelope, err := v.Seal("provider/123/source", []byte("secret-link-password"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		objectID string
		modify   func(*Envelope)
		want     error
	}{
		{"different object", "provider/456/source", nil, ErrAuthentication},
		{"different field", "provider/123/header", nil, ErrAuthentication},
		{"nonce", "provider/123/source", func(e *Envelope) { e.Nonce[0] ^= 1 }, ErrAuthentication},
		{"ciphertext", "provider/123/source", func(e *Envelope) { e.Ciphertext[0] ^= 1 }, ErrAuthentication},
		{"authentication tag", "provider/123/source", func(e *Envelope) { e.Ciphertext[len(e.Ciphertext)-1] ^= 1 }, ErrAuthentication},
		{"version", "provider/123/source", func(e *Envelope) { e.Version++ }, ErrInvalidEnvelope},
		{"algorithm", "provider/123/source", func(e *Envelope) { e.Algorithm = "none" }, ErrInvalidEnvelope},
		{"unknown key", "provider/123/source", func(e *Envelope) { e.KeyID = "missing" }, ErrUnknownKey},
		{"nonce size", "provider/123/source", func(e *Envelope) { e.Nonce = nil }, ErrInvalidEnvelope},
		{"short ciphertext", "provider/123/source", func(e *Envelope) { e.Ciphertext = []byte("short") }, ErrInvalidEnvelope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := envelope
			copy.Nonce = bytes.Clone(envelope.Nonce)
			copy.Ciphertext = bytes.Clone(envelope.Ciphertext)
			if tt.modify != nil {
				tt.modify(&copy)
			}
			plaintext, err := v.Open(tt.objectID, copy)
			if !errors.Is(err, tt.want) || plaintext != nil {
				t.Fatalf("got %v and plaintext %v, want %v and no plaintext", err, plaintext != nil, tt.want)
			}
			if strings.Contains(err.Error(), "secret-link-password") {
				t.Fatal("error exposes secret")
			}
		})
	}
	wrong, err := New("application-2026", testKey(0x43))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Open("provider/123/source", envelope); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestMissingKeyFailsClosed(t *testing.T) {
	var v *Vault
	if _, err := v.Seal("provider/id/source", []byte("credential")); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("nil seal: %v", err)
	}
	if _, err := v.Open("provider/id/source", Envelope{}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("nil open: %v", err)
	}
	if _, err := v.SealJSON("id", map[string]string{"password": "secret"}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("nil JSON seal: %v", err)
	}
	if _, err := New("active", nil); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := New("active", []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := NewKeyring("active", map[string][]byte{"old": testKey(1)}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing active key: %v", err)
	}
	if _, err := New("", testKey(1)); !errors.Is(err, ErrInvalidKeyID) {
		t.Fatalf("missing key ID: %v", err)
	}
}

func TestParseKeyDoesNotAcceptPassphrasesOrLeakConfiguration(t *testing.T) {
	externalKey := testKey(0x97)
	encoded := base64.StdEncoding.EncodeToString(externalKey)
	got, err := ParseKey(encoded)
	if err != nil || !bytes.Equal(got, externalKey) {
		t.Fatalf("parse external key: %v", err)
	}
	for _, input := range []string{"", "this-is-a-password", base64.StdEncoding.EncodeToString(testKey(1)[:31]), base64.StdEncoding.EncodeToString(append(testKey(1), 1)), "sensitive-malformed-key!"} {
		_, err := ParseKey(input)
		if err == nil {
			t.Fatal("accepted malformed key")
		}
		if input != "" && strings.Contains(err.Error(), input) {
			t.Fatal("error contains key configuration")
		}
	}
}

func TestKeyOwnershipAndSerialization(t *testing.T) {
	key := testKey(0xaa)
	v, err := New("active", key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := v.Seal("source", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if _, err := v.Open("source", envelope); err != nil {
		t.Fatalf("caller overwriting key changed vault: %v", err)
	}
	if _, err := json.Marshal(v); !errors.Is(err, ErrKeySerialization) {
		t.Fatalf("vault must not serialize: %v", err)
	}
	for _, value := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
		if value != "[secrets.Vault redacted]" {
			t.Fatalf("unsafe diagnostic format: %s", value)
		}
	}
}

func TestHistoricalKeyRotationAndMetadataBinding(t *testing.T) {
	old, err := New("old", testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := old.Seal("provider/1/source", []byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	rotating, err := NewKeyring("new", map[string][]byte{"old": testKey(1), "new": testKey(2)})
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := rotating.Rewrap("provider/1/source", envelope)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "old" || rewrapped.KeyID != "new" {
		t.Fatal("rewrap must not mutate old envelope")
	}
	newOnly, err := New("new", testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := newOnly.Open("provider/1/source", rewrapped); err != nil || string(got) != "credential" {
		t.Fatalf("rotated recovery failed: %v", err)
	}
	if _, err := newOnly.Open("provider/1/source", envelope); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("retired key read should fail: %v", err)
	}
	// Even aliases pointing at identical key bytes cannot substitute key IDs.
	aliases, err := NewKeyring("old", map[string][]byte{"old": testKey(1), "alias": testKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	envelope.KeyID = "alias"
	if _, err := aliases.Open("provider/1/source", envelope); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("key ID must be authenticated: %v", err)
	}
}

func TestJSONPrivateDTOAndSecretReferences(t *testing.T) {
	type privateDTO struct {
		Password string            `json:"password"`
		Headers  map[string]string `json:"headers"`
	}
	v := testVault(t)
	input := privateDTO{Password: "private-password", Headers: map[string]string{"Authorization": "Bearer private-token"}}
	envelope, err := v.SealJSON("lifecycle/v1", input)
	if err != nil {
		t.Fatal(err)
	}
	var got privateDTO
	if err := v.OpenJSON("lifecycle/v1", envelope, &got); err != nil {
		t.Fatal(err)
	}
	if got.Password != input.Password || got.Headers["Authorization"] != input.Headers["Authorization"] {
		t.Fatal("JSON credential recovery failed")
	}
	if _, err := v.SealJSON("lifecycle/v1", make(chan string)); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("invalid JSON: %v", err)
	}
	invalid, err := v.Seal("lifecycle/v1", []byte("not JSON private-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.OpenJSON("lifecycle/v1", invalid, &got); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("invalid decrypted JSON: %v", err)
	}
	a, err := NewSecretRef()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSecretRef()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != len("secret_")+32 {
		t.Fatal("invalid random secret reference")
	}
}

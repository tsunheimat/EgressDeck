// Package secrets encrypts persisted credentials with externally managed keys.
// Keys belong in runtime configuration or an external secret manager, never in
// the database or its backups. Public API objects should contain only SecretRef
// values; Envelope belongs exclusively in internal persistence records.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const (
	Version          = 1
	Algorithm        = "AES-256-GCM"
	KeySize          = 32
	MaxPlaintextSize = 16 << 20
)

var (
	ErrKeyUnavailable   = errors.New("application encryption key is not configured")
	ErrInvalidKey       = errors.New("application encryption key must contain exactly 32 bytes")
	ErrInvalidKeyID     = errors.New("encryption key ID must contain 1 to 128 printable characters")
	ErrUnknownKey       = errors.New("encrypted secret requires an unavailable encryption key")
	ErrInvalidObjectID  = errors.New("secret object ID must contain 1 to 4096 characters")
	ErrInvalidEnvelope  = errors.New("invalid or unsupported encrypted secret envelope")
	ErrAuthentication   = errors.New("encrypted secret authentication failed")
	ErrTooLarge         = errors.New("secret exceeds the 16 MiB limit")
	ErrInvalidJSON      = errors.New("secret JSON encoding or decoding failed")
	ErrKeySerialization = errors.New("application encryption keys cannot be serialized")
)

// SecretRef is an opaque identifier that is safe to include in public metadata.
// It is not a credential and must not by itself authorize secret retrieval.
type SecretRef string

// NewSecretRef creates a random identifier independent of credential contents.
func NewSecretRef() (SecretRef, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("secret reference generation failed")
	}
	return SecretRef("secret_" + hex.EncodeToString(value[:])), nil
}

// Envelope is the entire persisted encryption format. Its byte slices use the
// standard JSON base64 encoding. Object IDs are supplied by the caller on read
// and authenticated rather than trusted from the stored record itself.
type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Vault holds an active encryption key and optional historical decryption keys.
// It is immutable after construction and safe for concurrent use.
type Vault struct {
	activeID string
	keys     map[string]cipher.AEAD
}

// New creates a vault from a caller-supplied 256-bit key. A missing key fails
// closed; the package never generates an implicit or development fallback key.
func New(keyID string, key []byte) (*Vault, error) {
	return NewKeyring(keyID, map[string][]byte{keyID: key})
}

// NewKeyring keeps historical keys available during rotation. New ciphertext
// always uses activeID. The caller may overwrite its key buffers after return.
func NewKeyring(activeID string, keys map[string][]byte) (*Vault, error) {
	if len(keys) == 0 {
		return nil, ErrKeyUnavailable
	}
	if !validKeyID(activeID) {
		return nil, ErrInvalidKeyID
	}
	if _, exists := keys[activeID]; !exists {
		return nil, ErrKeyUnavailable
	}
	v := &Vault{activeID: activeID, keys: make(map[string]cipher.AEAD, len(keys))}
	for id, key := range keys {
		if !validKeyID(id) {
			return nil, ErrInvalidKeyID
		}
		if len(key) == 0 {
			return nil, ErrKeyUnavailable
		}
		if len(key) != KeySize {
			return nil, ErrInvalidKey
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrInvalidKey
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrInvalidKey
		}
		v.keys[id] = aead
	}
	return v, nil
}

// ParseKey decodes a standard base64 runtime configuration value. Passphrases,
// hashes of short strings, and implicit key generation are deliberately absent.
func ParseKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, ErrKeyUnavailable
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != KeySize {
		clear(key)
		return nil, ErrInvalidKey
	}
	return key, nil
}

func validKeyID(id string) bool {
	if len(id) == 0 || len(id) > 128 || strings.TrimSpace(id) != id {
		return false
	}
	for _, c := range id {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func validObjectID(id string) bool {
	return strings.TrimSpace(id) != "" && len(id) <= 4096
}

// ActiveKeyID reports non-secret metadata for rotation status.
func (v *Vault) ActiveKeyID() string {
	if v == nil {
		return ""
	}
	return v.activeID
}

// Seal encrypts plaintext with a new random nonce. objectID must include the
// object namespace and field/purpose (for example "provider/<uuid>/source").
// Supplying the identical ID on Open prevents ciphertext swapping across rows,
// fields, or document types. Errors never contain plaintext or object IDs.
func (v *Vault) Seal(objectID string, plaintext []byte) (Envelope, error) {
	if v == nil || v.keys[v.activeID] == nil {
		return Envelope{}, ErrKeyUnavailable
	}
	if !validObjectID(objectID) {
		return Envelope{}, ErrInvalidObjectID
	}
	if len(plaintext) > MaxPlaintextSize {
		return Envelope{}, ErrTooLarge
	}
	aead := v.keys[v.activeID]
	envelope := Envelope{Version: Version, Algorithm: Algorithm, KeyID: v.activeID, Nonce: make([]byte, aead.NonceSize())}
	if _, err := rand.Read(envelope.Nonce); err != nil {
		return Envelope{}, errors.New("secret nonce generation failed")
	}
	envelope.Ciphertext = aead.Seal(nil, envelope.Nonce, plaintext, authenticatedData(objectID, envelope))
	return envelope, nil
}

// Open authenticates the entire envelope and its caller-supplied object ID
// before returning plaintext. A nil or unconfigured Vault always fails closed.
func (v *Vault) Open(objectID string, envelope Envelope) ([]byte, error) {
	if v == nil || len(v.keys) == 0 {
		return nil, ErrKeyUnavailable
	}
	if !validObjectID(objectID) {
		return nil, ErrInvalidObjectID
	}
	if envelope.Version != Version || envelope.Algorithm != Algorithm || !validKeyID(envelope.KeyID) {
		return nil, ErrInvalidEnvelope
	}
	aead := v.keys[envelope.KeyID]
	if aead == nil {
		return nil, ErrUnknownKey
	}
	if len(envelope.Nonce) != aead.NonceSize() || len(envelope.Ciphertext) < aead.Overhead() || len(envelope.Ciphertext) > MaxPlaintextSize+aead.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, authenticatedData(objectID, envelope))
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// SealJSON is for explicit private persistence DTOs, which must include all
// credentials needed after restart. Public structs with json:"-" secret fields
// cannot recover those fields through this helper. Only Envelope is persisted.
func (v *Vault) SealJSON(objectID string, value any) (Envelope, error) {
	if v == nil || len(v.keys) == 0 {
		return Envelope{}, ErrKeyUnavailable
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return Envelope{}, ErrInvalidJSON
	}
	defer clear(plaintext)
	return v.Seal(objectID, plaintext)
}

// OpenJSON authenticates before decoding and clears its temporary plaintext
// buffer. The caller owns the decoded private DTO and must not expose it through
// API responses, logs, audit events, operation results, or support exports.
func (v *Vault) OpenJSON(objectID string, envelope Envelope, value any) error {
	plaintext, err := v.Open(objectID, envelope)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	if err := json.Unmarshal(plaintext, value); err != nil {
		return ErrInvalidJSON
	}
	return nil
}

// Rewrap authenticates old ciphertext and encrypts it under the active key.
// The caller must atomically persist the result before retiring any old key;
// this method never mutates the supplied envelope.
func (v *Vault) Rewrap(objectID string, envelope Envelope) (Envelope, error) {
	plaintext, err := v.Open(objectID, envelope)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(plaintext)
	return v.Seal(objectID, plaintext)
}

// Refuse accidental inclusion of key holders in JSON backups or diagnostics.
func (v *Vault) MarshalJSON() ([]byte, error) { return nil, ErrKeySerialization }
func (v *Vault) String() string               { return "[secrets.Vault redacted]" }
func (v *Vault) GoString() string             { return v.String() }

func authenticatedData(objectID string, envelope Envelope) []byte {
	// Length prefixes prevent ambiguous pairs such as ("a/b", "c") and
	// ("a", "b/c") from sharing an authentication context.
	data := []byte("egressdeck/secrets\x00")
	data = binary.BigEndian.AppendUint32(data, uint32(envelope.Version))
	for _, value := range []string{envelope.Algorithm, envelope.KeyID, objectID} {
		data = binary.BigEndian.AppendUint32(data, uint32(len(value)))
		data = append(data, value...)
	}
	return data
}

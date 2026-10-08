package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

const encryptedJournalFormat = "egressdeck/deployment-journal"
const encryptedJournalObjectID = "deployment/journal/v1"

var (
	ErrPlaintextJournal           = errors.New("deployment journal contains legacy plaintext; explicitly migrate it to encrypted storage before opening")
	ErrEncryptedJournal           = errors.New("deployment journal is encrypted; open it with OpenEncryptedFileJournal and its external application key")
	ErrInvalidJournal             = errors.New("invalid or unsupported deployment journal")
	ErrMigrationDestinationExists = errors.New("journal migration destination already exists; choose a new path")
)

// OpenEncryptedFileJournal uses the same atomic replacement, idempotency, and
// fencing semantics as FileJournal while encrypting its complete snapshots.
// The path identifies a single-controller journal. Associated data binds the
// journal's purpose/version, independently of the path so backups can be
// restored to another directory with their separately recovered external key.
//
// Existing plaintext journals are deliberately rejected, never silently
// rewritten or opened as empty state. Their migration must be explicit while
// the controller is stopped. Opening never creates, modifies, or migrates a
// file, including when decryption fails.
func OpenEncryptedFileJournal(path string, vault *secrets.Vault) (*FileJournal, error) {
	if vault == nil || vault.ActiveKeyID() == "" {
		return nil, secrets.ErrKeyUnavailable
	}
	return openFileJournal(path, encryptedFileJournalCodec{vault: vault})
}

// MigratePlainFileJournal explicitly converts a stopped controller's legacy
// plaintext journal to a distinct encrypted file. The original is never
// modified. The destination becomes visible only after the ciphertext has been
// synced; a hard link publishes it without replacing any existing destination.
// Filesystems that do not support same-directory hard links fail safely.
func MigratePlainFileJournal(sourcePath, destinationPath string, vault *secrets.Vault) error {
	if vault == nil || vault.ActiveKeyID() == "" {
		return secrets.ErrKeyUnavailable
	}
	if sourcePath == "" || destinationPath == "" {
		return fmt.Errorf("%w: source and destination paths are required", ErrInvalidRequest)
	}
	if _, err := os.Lstat(destinationPath); err == nil {
		return ErrMigrationDestinationExists
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect journal migration destination: %w", err)
	}
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read legacy deployment journal: %w", err)
	}
	defer clear(raw)
	data, err := decodePlainFileJournal(raw)
	if err != nil {
		return err
	}
	ciphertext, err := (encryptedFileJournalCodec{vault: vault}).encode(data)
	if err != nil {
		return err
	}
	directory := filepath.Dir(destinationPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create journal migration directory: %w", err)
	}
	tmp, err := os.CreateTemp(directory, ".deployment-journal-migration-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), destinationPath); err != nil {
		if os.IsExist(err) {
			return ErrMigrationDestinationExists
		}
		return fmt.Errorf("publish encrypted deployment journal: %w", err)
	}
	return nil
}

type encryptedFileJournalCodec struct{ vault *secrets.Vault }

type encryptedFileJournalDocument struct {
	Format   string           `json:"format"`
	Version  int              `json:"version"`
	Envelope secrets.Envelope `json:"envelope"`
}

func (c encryptedFileJournalCodec) encode(data fileJournalData) ([]byte, error) {
	envelope, err := c.vault.SealJSON(encryptedJournalObjectID, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt deployment journal: %w", err)
	}
	return json.Marshal(encryptedFileJournalDocument{Format: encryptedJournalFormat, Version: 1, Envelope: envelope})
}

func (c encryptedFileJournalCodec) decode(raw []byte) (fileJournalData, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return fileJournalData{}, ErrInvalidJournal
	}
	if _, legacy := fields["operations"]; legacy {
		return fileJournalData{}, ErrPlaintextJournal
	}
	if _, legacy := fields["by_key"]; legacy {
		return fileJournalData{}, ErrPlaintextJournal
	}
	if _, legacy := fields["fences"]; legacy {
		return fileJournalData{}, ErrPlaintextJournal
	}
	var document encryptedFileJournalDocument
	if err := decodeJournalJSON(raw, &document); err != nil || document.Format != encryptedJournalFormat || document.Version != 1 {
		return fileJournalData{}, ErrInvalidJournal
	}
	plaintext, err := c.vault.Open(encryptedJournalObjectID, document.Envelope)
	if err != nil {
		return fileJournalData{}, fmt.Errorf("decrypt deployment journal: %w", err)
	}
	defer clear(plaintext)
	return decodeJournalSnapshot(plaintext)
}

func decodePlainFileJournal(raw []byte) (fileJournalData, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return fileJournalData{}, ErrInvalidJournal
	}
	if _, encrypted := fields["envelope"]; encrypted {
		return fileJournalData{}, ErrEncryptedJournal
	}
	if _, encrypted := fields["ciphertext"]; encrypted {
		return fileJournalData{}, ErrEncryptedJournal
	}
	return decodeJournalSnapshot(raw)
}

func decodeJournalSnapshot(raw []byte) (fileJournalData, error) {
	var data fileJournalData
	if err := decodeJournalJSON(raw, &data); err != nil || data.Operations == nil || data.ByKey == nil || data.Fences == nil {
		return fileJournalData{}, ErrInvalidJournal
	}
	return data, nil
}

func decodeJournalJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalidJournal
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrInvalidJournal
	}
	return nil
}

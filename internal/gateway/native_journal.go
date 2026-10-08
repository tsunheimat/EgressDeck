package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const nativeJournalLimit = 24 << 20
const nativeJournalMetadataLimit = 63

// NativeFileJournal atomically keeps the latest encrypted recovery state and
// 63 metadata records. It is used only by native mode: total retained bytes and
// operation count cannot grow with the number of provider refreshes.
type NativeFileJournal struct {
	mu   sync.Mutex
	path string
}

func NewNativeFileJournal(path string) *NativeFileJournal { return &NativeFileJournal{path: path} }
func (j *NativeFileJournal) read() ([]JournalEntry, error) {
	info, err := os.Lstat(j.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("native journal must be a private regular file")
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("native journal owner differs from the agent")
	}
	f, err := os.Open(j.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > nativeJournalLimit {
		return nil, errors.New("native journal file is invalid or too large")
	}
	scan := bufio.NewScanner(io.LimitReader(f, nativeJournalLimit+1))
	scan.Buffer(make([]byte, 4096), nativeJournalLimit)
	var entries []JournalEntry
	for scan.Scan() {
		var entry JournalEntry
		if len(scan.Bytes()) == 0 {
			continue
		}
		if json.Unmarshal(scan.Bytes(), &entry) != nil {
			return nil, errors.New("native journal record is invalid")
		}
		entries = append(entries, entry)
		if len(entries) > nativeJournalMetadataLimit+1 {
			return nil, errors.New("native journal contains too many records")
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
func (j *NativeFileJournal) Entries(context.Context) ([]JournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.read()
}
func (j *NativeFileJournal) Append(ctx context.Context, entry JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !filepath.IsAbs(j.path) {
		return errors.New("native journal requires an absolute path")
	}
	if entry.Operation != "native.state" || len(entry.State) == 0 {
		return errors.New("native journal accepts encrypted recovery records only")
	}
	var envelope struct {
		Version    int    `json:"version"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if json.Unmarshal(entry.State, &envelope) != nil || envelope.Version != 1 || len(envelope.Ciphertext) == 0 {
		return errors.New("native journal requires encrypted state")
	}
	parent := filepath.Dir(j.path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0700 {
		return errors.New("native journal parent must be a private directory")
	}
	if owner, ok := parentInfo.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("native journal parent owner differs from the agent")
	}
	if info, err := os.Lstat(j.path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("native journal must be a private regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := j.read()
	if err != nil {
		return err
	}
	if len(entries) >= nativeJournalMetadataLimit {
		entries = entries[len(entries)-nativeJournalMetadataLimit:]
	}
	for i := range entries {
		entries[i].State = nil
	}
	entries = append(entries, entry)
	encoded := make([]byte, 0)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		encoded = append(encoded, b...)
		encoded = append(encoded, '\n')
	}
	if len(encoded) > nativeJournalLimit {
		return errors.New("native journal exceeds its retained byte limit")
	}
	file, err := os.CreateTemp(parent, ".native-journal-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err = file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, j.path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

var _ Journal = (*NativeFileJournal)(nil)

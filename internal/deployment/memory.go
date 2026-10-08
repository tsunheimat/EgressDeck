package deployment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

// MemoryJournal is a deterministic durable-journal substitute. It is safe for
// concurrent callers and clones operations at every boundary, so tests catch
// accidental mutation of persisted state. A production journal should preserve
// the same compare/fence semantics in a database transaction.
type MemoryJournal struct {
	mu     sync.RWMutex
	ops    map[string]Operation
	byKey  map[string]string
	fences map[string]uint64
}

func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{ops: make(map[string]Operation), byKey: make(map[string]string), fences: make(map[string]uint64)}
}

func (j *MemoryJournal) Create(_ context.Context, op Operation) (Operation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if op.ID == "" {
		op.ID = domain.NewID()
	}
	if _, ok := j.ops[op.ID]; ok {
		return Operation{}, fmt.Errorf("%w: operation %s already exists", ErrConflict, op.ID)
	}
	if op.IdempotencyKey != "" {
		key := op.Target.Key() + "\x00" + op.IdempotencyKey
		if old := j.byKey[key]; old != "" {
			prior := j.ops[old]
			if prior.RequestHash != "" && op.RequestHash != "" && prior.RequestHash != op.RequestHash {
				return Operation{}, fmt.Errorf("%w: idempotency key is already bound to another request", ErrConflict)
			}
			return prior.Clone(), nil
		}
		j.byKey[key] = op.ID
	}
	if op.Status == "" {
		op.Status = StatusDraft
	}
	if op.Rollback == "" {
		op.Rollback = RollbackNone
	}
	if op.CreatedAt.IsZero() {
		op.CreatedAt = time.Now().UTC()
	}
	op.UpdatedAt = op.CreatedAt
	j.ops[op.ID] = op.Clone()
	return op.Clone(), nil
}

func (j *MemoryJournal) Get(_ context.Context, id string) (Operation, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	op, ok := j.ops[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return op.Clone(), nil
}

func (j *MemoryJournal) Save(_ context.Context, op Operation) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.ops[op.ID]; !ok {
		return ErrNotFound
	}
	if current := j.fences[op.Target.Key()]; op.FenceToken != 0 && current > op.FenceToken && op.Status != StatusOutcomeUnknown {
		return ErrFenceLost
	}
	if op.UpdatedAt.IsZero() {
		op.UpdatedAt = time.Now().UTC()
	}
	j.ops[op.ID] = op.Clone()
	if op.IdempotencyKey != "" {
		j.byKey[op.Target.Key()+"\x00"+op.IdempotencyKey] = op.ID
	}
	return nil
}

func (j *MemoryJournal) FindByIdempotency(_ context.Context, target Target, key string) (Operation, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	id := j.byKey[target.Key()+"\x00"+key]
	if id == "" {
		return Operation{}, ErrNotFound
	}
	return j.ops[id].Clone(), nil
}

func (j *MemoryJournal) List(_ context.Context) ([]Operation, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	out := make([]Operation, 0, len(j.ops))
	for _, op := range j.ops {
		out = append(out, op.Clone())
	}
	return sortedOperations(out), nil
}

func (j *MemoryJournal) NextFence(_ context.Context, target Target) (Fence, error) {
	if !target.Valid() {
		return Fence{}, fmt.Errorf("%w: invalid target", ErrInvalidRequest)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.fences[target.Key()]++
	return Fence{Target: target, Token: j.fences[target.Key()]}, nil
}

func (j *MemoryJournal) FenceCurrent(_ context.Context, target Target, token uint64) (bool, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return token != 0 && j.fences[target.Key()] == token, nil
}

// FileJournal provides restart persistence without requiring PostgreSQL. It
// uses the same journal semantics as MemoryJournal and atomically replaces a
// JSON file after each mutation. It is intended for a single controller
// process/bootstrap deployment; PostgreSQL remains the multi-instance store.
type FileJournal struct {
	*MemoryJournal
	path  string
	write sync.Mutex
	codec fileJournalCodec
}

type fileJournalCodec interface {
	encode(fileJournalData) ([]byte, error)
	decode([]byte) (fileJournalData, error)
}

type fileJournalData struct {
	Operations map[string]Operation `json:"operations"`
	ByKey      map[string]string    `json:"by_key"`
	Fences     map[string]uint64    `json:"fences"`
}

func OpenFileJournal(path string) (*FileJournal, error) {
	return openFileJournal(path, nil)
}

func openFileJournal(path string, codec fileJournalCodec) (*FileJournal, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: journal path is required", ErrInvalidRequest)
	}
	j := &FileJournal{MemoryJournal: NewMemoryJournal(), path: path, codec: codec}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	var data fileJournalData
	if codec != nil {
		data, err = codec.decode(b)
	} else {
		data, err = decodePlainFileJournal(b)
	}
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	if data.Operations != nil {
		j.ops = data.Operations
	}
	if data.ByKey != nil {
		j.byKey = data.ByKey
	}
	if data.Fences != nil {
		j.fences = data.Fences
	}
	j.mu.Unlock()
	return j, nil
}

func (j *FileJournal) persist() error {
	return j.persistSnapshot(j.snapshot())
}

func (j *FileJournal) snapshot() fileJournalData {
	j.mu.RLock()
	data := fileJournalData{Operations: make(map[string]Operation, len(j.ops)), ByKey: make(map[string]string, len(j.byKey)), Fences: make(map[string]uint64, len(j.fences))}
	for id, op := range j.ops {
		data.Operations[id] = op.Clone()
	}
	for key, id := range j.byKey {
		data.ByKey[key] = id
	}
	for key, token := range j.fences {
		data.Fences[key] = token
	}
	j.mu.RUnlock()
	return data
}

func (j *FileJournal) restore(data fileJournalData) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ops, j.byKey, j.fences = data.Operations, data.ByKey, data.Fences
}

func (j *FileJournal) persistSnapshot(data fileJournalData) error {
	var b []byte
	var err error
	if j.codec != nil {
		b, err = j.codec.encode(data)
	} else {
		b, err = json.MarshalIndent(data, "", "  ")
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(j.path), ".deployment-journal-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
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
	return os.Rename(tmpName, j.path)
}

func (j *FileJournal) Create(ctx context.Context, op Operation) (Operation, error) {
	j.write.Lock()
	defer j.write.Unlock()
	before := j.snapshot()
	out, err := j.MemoryJournal.Create(ctx, op)
	if err != nil {
		return Operation{}, err
	}
	if err := j.persist(); err != nil {
		j.restore(before)
		return Operation{}, err
	}
	return out, nil
}

func (j *FileJournal) Save(ctx context.Context, op Operation) error {
	j.write.Lock()
	defer j.write.Unlock()
	before := j.snapshot()
	if err := j.MemoryJournal.Save(ctx, op); err != nil {
		return err
	}
	if err := j.persist(); err != nil {
		j.restore(before)
		return err
	}
	return nil
}

func (j *FileJournal) NextFence(ctx context.Context, target Target) (Fence, error) {
	j.write.Lock()
	defer j.write.Unlock()
	before := j.snapshot()
	fence, err := j.MemoryJournal.NextFence(ctx, target)
	if err != nil {
		return Fence{}, err
	}
	if err := j.persist(); err != nil {
		j.restore(before)
		return Fence{}, err
	}
	return fence, nil
}

func (j *FileJournal) Get(ctx context.Context, id string) (Operation, error) {
	j.write.Lock()
	defer j.write.Unlock()
	return j.MemoryJournal.Get(ctx, id)
}

func (j *FileJournal) List(ctx context.Context) ([]Operation, error) {
	j.write.Lock()
	defer j.write.Unlock()
	return j.MemoryJournal.List(ctx)
}

func (j *FileJournal) FindByIdempotency(ctx context.Context, target Target, key string) (Operation, error) {
	j.write.Lock()
	defer j.write.Unlock()
	return j.MemoryJournal.FindByIdempotency(ctx, target, key)
}

func (j *FileJournal) FenceCurrent(ctx context.Context, target Target, token uint64) (bool, error) {
	j.write.Lock()
	defer j.write.Unlock()
	return j.MemoryJournal.FenceCurrent(ctx, target, token)
}

package correlate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// FileKnownIPs is a thread-safe set of IPs persisted as a sorted JSON
// array. Writes are atomic via temp-file-and-rename.
//
// Trade-off: we re-write the whole file on every Add. For typical VPS
// owners with <1000 unique source IPs over a year, this is fine. If a
// future user complains about disk thrash, swap in an append-only log
// or BoltDB without changing the interface.
type FileKnownIPs struct {
	path string

	mu  sync.RWMutex
	set map[string]struct{}
}

// NewFileKnownIPs loads (or initializes) the on-disk known-IP set.
// Missing or empty file is not an error.
func NewFileKnownIPs(path string) (*FileKnownIPs, error) {
	k := &FileKnownIPs{path: path, set: map[string]struct{}{}}
	if path == "" {
		return k, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("known_ips: mkdir state dir: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return k, nil
		}
		return nil, fmt.Errorf("known_ips: read %q: %w", path, err)
	}
	if len(b) == 0 {
		return k, nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("known_ips: parse %q: %w", path, err)
	}
	for _, ip := range list {
		k.set[ip] = struct{}{}
	}
	return k, nil
}

func (k *FileKnownIPs) Has(ip string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.set[ip]
	return ok
}

func (k *FileKnownIPs) Add(ip string) {
	if ip == "" {
		return
	}
	k.mu.Lock()
	if _, ok := k.set[ip]; ok {
		k.mu.Unlock()
		return
	}
	k.set[ip] = struct{}{}
	snapshot := make([]string, 0, len(k.set))
	for ip := range k.set {
		snapshot = append(snapshot, ip)
	}
	k.mu.Unlock()

	if k.path == "" {
		return
	}
	sort.Strings(snapshot)
	if err := writeJSONAtomic(k.path, snapshot); err != nil {
		// Best-effort: a write failure does not invalidate the in-memory
		// set; the user just loses persistence. Log via the agent's
		// general error path is overkill here.
		return
	}
}

// MemoryKnownIPs is a non-persisting implementation, useful for tests.
type MemoryKnownIPs struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

func NewMemoryKnownIPs() *MemoryKnownIPs {
	return &MemoryKnownIPs{set: map[string]struct{}{}}
}

func (m *MemoryKnownIPs) Has(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.set[ip]
	return ok
}

func (m *MemoryKnownIPs) Add(ip string) {
	if ip == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set[ip] = struct{}{}
}

func writeJSONAtomic(path string, v any) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".knownips-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

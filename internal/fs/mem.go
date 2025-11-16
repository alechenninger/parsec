package fs

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// ErrNotExist is returned when a file does not exist
	ErrNotExist = errors.New("file does not exist")
)

// MemFileSystem is an in-memory filesystem for testing
type MemFileSystem struct {
	mu    sync.RWMutex
	files map[string][]byte // path -> content
	dirs  map[string]bool   // path -> exists
}

// NewMemFileSystem creates a new in-memory filesystem
func NewMemFileSystem() *MemFileSystem {
	return &MemFileSystem{
		files: make(map[string][]byte),
		dirs:  make(map[string]bool),
	}
}

// MkdirAll creates a directory and all necessary parents
func (f *MemFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Mark all parent directories as existing
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		f.dirs[current] = true
	}
	return nil
}

// ReadFile reads the entire file
func (f *MemFileSystem) ReadFile(name string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	data, ok := f.files[name]
	if !ok {
		return nil, ErrNotExist
	}

	// Return a copy to prevent external modifications
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// WriteFileAtomic writes data to a file atomically
// For in-memory filesystem, this is just a direct write
func (f *MemFileSystem) WriteFileAtomic(name string, data []byte, perm fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Make a copy to prevent external modifications
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	f.files[name] = dataCopy
	return nil
}

// IsNotExist returns true if the error indicates a file doesn't exist
func (f *MemFileSystem) IsNotExist(err error) bool {
	return errors.Is(err, ErrNotExist)
}

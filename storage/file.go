package storage

import (
	"os"
)

type fileStorage struct {
	path string
	perm os.FileMode
}

func NewFileStorage(path string, perm os.FileMode) Storage {
	return &fileStorage{
		path: path,
		perm: perm,
	}
}

// func (f *fileStorage) path(key string) string {
// 	return filepath.Join(f.basePath, key)
// }

// Read implements [Storage].
func (f *fileStorage) Read() ([]byte, error) {
	data, err := os.ReadFile(f.path)
	return data, err
}

// Write implements [Storage].
func (f *fileStorage) Write(value []byte) error {
	return os.WriteFile(f.path, value, f.perm)
}

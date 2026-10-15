package storage

import (
	"os"
)

type fileStorage struct {
	path string
}

func NewFileStorage(path string) Storage {
	return &fileStorage{
		path: path,
	}
}

// func (f *fileStorage) path(key string) string {
// 	return filepath.Join(f.basePath, key)
// }

// Read implements [Storage].
func (f *fileStorage) Read() (string, error) {
	data, err := os.ReadFile(f.path)
	return string(data), err
}

// Write implements [Storage].
func (f *fileStorage) Write(value string) error {
	return os.WriteFile(f.path, []byte(value), 0o600)
}

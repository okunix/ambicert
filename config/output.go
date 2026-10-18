package config

import (
	"errors"
	"os"

	"github.com/okunix/ambicert/storage"
)

var (
	ErrUnsupportedOutput     = errors.New("output is not supported")
	ErrOutputIsNotConfigured = errors.New("output is not configured")
)

type VaultOutputConfig struct {
	Address string `yaml:"address"`
	CACert  string `yaml:"caCert"`
	Token   string `yaml:"token"`
	Path    string `yaml:"path"`
	Key     string `yaml:"key"`
}

type FileOutputConfig struct {
	Path string       `yaml:"path"`
	Perm *os.FileMode `yaml:"perm,omitempty"`
}

type OutputConfig struct {
	Type  string             `yaml:"type"`
	Vault *VaultOutputConfig `yaml:"vault,omitempty"`
	File  *FileOutputConfig  `yaml:"file,omitempty"`
}

func (o OutputConfig) Output() (storage.Writable, error) {
	switch o.Type {
	case "file":
		if o.File == nil {
			return nil, ErrOutputIsNotConfigured
		}
		var perm os.FileMode = 0600
		if o.File.Perm != nil {
			perm = *o.File.Perm
		}
		return storage.NewFileStorage(o.File.Path, perm), nil
	case "stdout":
		return storage.NewStdout(), nil
	case "vault":
	}
	return nil, ErrUnsupportedOutput
}

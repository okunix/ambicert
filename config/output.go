package config

import (
	"errors"

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
	Path string `yaml:"path"`
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
		return storage.NewFileStorage(o.File.Path), nil
	case "stdout":
		return storage.NewStdout(), nil
	case "vault":
	}
	return nil, ErrUnsupportedOutput
}

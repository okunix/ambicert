package storage

import (
	"fmt"
)

type stdoutStorage struct {
}

func NewStdout() Writable {
	return &stdoutStorage{}
}

func (f *stdoutStorage) Write(value []byte) error {
	fmt.Print(string(value))
	return nil
}

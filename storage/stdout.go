package storage

import (
	"fmt"
)

type stdoutStorage struct {
}

func NewStdout() Writable {
	return &stdoutStorage{}
}

func (f *stdoutStorage) Write(value string) error {
	fmt.Print(value)
	return nil
}

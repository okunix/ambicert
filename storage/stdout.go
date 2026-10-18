package storage

import (
	"context"
	"fmt"
)

type stdoutStorage struct {
}

func NewStdout() Writable {
	return &stdoutStorage{}
}

func (f *stdoutStorage) Write(ctx context.Context, value []byte) error {
	fmt.Print(string(value))
	return nil
}

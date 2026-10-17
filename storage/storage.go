package storage

import "context"

type Readable interface {
	Read(ctx context.Context) ([]byte, error)
}

type Writable interface {
	Write(ctx context.Context, value []byte) error
}

// per key storage interface
type Storage interface {
	Readable
	Writable
}

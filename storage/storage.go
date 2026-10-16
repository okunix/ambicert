package storage

type Readable interface {
	Read() ([]byte, error)
}

type Writable interface {
	Write(value []byte) error
}

// per key storage interface
type Storage interface {
	Readable
	Writable
}

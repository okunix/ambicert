package storage

type Readable interface {
	Read() (string, error)
}

type Writable interface {
	Write(value string) error
}

// per key storage interface
type Storage interface {
	Readable
	Writable
}

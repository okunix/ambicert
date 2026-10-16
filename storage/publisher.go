package storage

import (
	"bytes"
	"crypto"

	"github.com/okunix/ambicert/pemutil"
)

func publish(data []byte, outputs ...Writable) error {
	for _, v := range outputs {
		if err := v.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// Encodes in PEM and pushes to storage
func PublishPrivateKey(privatekey crypto.PrivateKey, outputs ...Writable) error {
	var buf bytes.Buffer
	err := pemutil.EncodePrivateKey(&buf, privatekey)
	if err != nil {
		return err
	}
	return publish(buf.Bytes(), outputs...)
}

// Encodes in PEM and pushes to storage
func PublishCertificateRequest(csrDER []byte, outputs ...Writable) error {
	var buf bytes.Buffer
	err := pemutil.EncodeCertificateRequest(&buf, csrDER)
	if err != nil {
		return err
	}
	return publish(buf.Bytes(), outputs...)
}

package storage

import (
	"bytes"
	"context"
	"crypto"

	"github.com/okunix/ambicert/pemutil"
)

func publish(ctx context.Context, data []byte, outputs ...Writable) error {
	for _, v := range outputs { // make this concurrent
		if err := v.Write(ctx, data); err != nil {
			return err
		}
	}
	return nil
}

// Encodes in PEM and pushes to storage
func PublishPrivateKey(ctx context.Context, privatekey crypto.PrivateKey, outputs ...Writable) error {
	var buf bytes.Buffer
	err := pemutil.EncodePrivateKey(&buf, privatekey)
	if err != nil {
		return err
	}
	return publish(ctx, buf.Bytes(), outputs...)
}

// Encodes in PEM and pushes to storage
func PublishCertificateRequest(ctx context.Context, csrDER []byte, outputs ...Writable) error {
	var buf bytes.Buffer
	err := pemutil.EncodeCertificateRequest(&buf, csrDER)
	if err != nil {
		return err
	}
	return publish(ctx, buf.Bytes(), outputs...)
}

package pemutil

import (
	"crypto/x509"
	"encoding/pem"
	"io"
)

func Encode(w io.Writer, block string, data []byte) error {
	return pem.Encode(w, &pem.Block{Type: block, Bytes: data})
}

func EncodeCertificateRequest(w io.Writer, csr []byte) error {
	return Encode(w, "CERTIFICATE REQUEST", csr)
}

func EncodePrivateKey(w io.Writer, key any) error {
	// Encoding key to der
	keyder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	return Encode(w, "PRIVATE KEY", keyder)
}

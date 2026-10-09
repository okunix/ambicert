package csr

import (
	"crypto/x509"
	"encoding/asn1"
)

type KeyUsage struct {
	Values   []string `yaml:"values"`
	Critical bool     `yaml:"critical,omitempty"`
}

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

	oidServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidOCSPSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

func keyUsageDER(ku x509.KeyUsage) ([]byte, error) {
	// x509.KeyUsage uses bit i = 1<<i, LSB-first, so reverse into DER's MSB-first order
	var a [2]byte
	for i := 0; i < 9; i++ {
		if ku&(1<<uint(i)) != 0 {
			a[i/8] |= 0x80 >> uint(i%8)
		}
	}
	l := 2
	if a[1] == 0 {
		l = 1
	}
	// BitLength = highest set bit + 1
	n := 0
	for i := 8; i >= 0; i-- {
		if ku&(1<<uint(i)) != 0 {
			n = i + 1
			break
		}
	}
	return asn1.Marshal(asn1.BitString{Bytes: a[:l], BitLength: n})
}

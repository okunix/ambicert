package csr

import (
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

	oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func rawEKUtoDER(rawEKUs []string) ([]byte, error) {
	ekus := make(asn1.ObjectIdentifier, 0)
	for _, eku := range rawEKUs {
		switch eku {
		case "serverAuth":
			ekus = append(ekus, oidServerAuth...)
		case "clientAuth":
			ekus = append(ekus, oidClientAuth...)
		case "codeSigning":
			fallthrough
		case "emailProtection":
			fallthrough
		case "timeStamping":
			fallthrough
		case "OCSPSigning":
			fallthrough
		case "ipsecIKE":
			fallthrough
		case "msCodeInd":
			fallthrough
		case "msCodeCom":
			fallthrough
		case "msCTLSign":
			fallthrough
		case "msEFS":
			fallthrough
		default:
		}
	}
	if len(ekus) == 0 {
		return nil, nil
	}
	return asn1.Marshal(ekus)
}

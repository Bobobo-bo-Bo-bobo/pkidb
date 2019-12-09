package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"
)

// GenerateCRL - generate CRL
func GenerateCRL(cfg *PKIConfiguration) ([]byte, error) {
	var crlExpire time.Time

	revoked, err := cfg.DBBackend.GetRevokedCertificates(cfg)
	if err != nil {
        return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	revlist, err := buildRevokecCertificateList(revoked)
	if err != nil {
        return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	crlExpire = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(cfg.Global.CrlValidtyPeriod))

	crl, err := cfg.CRLPublicKey.CreateCRL(rand.Reader, cfg.CRLCertificate.PrivateKey, revlist, time.Now(), crlExpire)
	if err != nil {
        return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return crl, nil
}

func buildRevokecCertificateList(rr []RevokeRequest) ([]pkix.RevokedCertificate, error) {
	var list = make([]pkix.RevokedCertificate, 0)

	for _, r := range rr {
		reasonCode, found := RevocationReasonMap[strings.ToLower(r.Reason)]
		if !found {
            return nil, fmt.Errorf("%s: Invalid revocation reason %s", GetFrame(), r.Reason)
		}

		oid, err := StringToASN1ObjectIdentifier(OIDCRLReason)
		if err != nil {
            return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		l := pkix.RevokedCertificate{
			SerialNumber:   r.SerialNumber,
			RevocationTime: r.Time,
			Extensions:     make([]pkix.Extension, 1),
		}

		ext := pkix.Extension{
			Id:       oid,
			Critical: false,
			Value:    make([]byte, 3),
		}

		// Note: There is no need to fireup the ASN1 encoder for CRLReason because we know
		//       the DER encoded data:
		ext.Value[0] = 0x0a // type: enumeration
		ext.Value[1] = 0x01 // length: 1 byte
		ext.Value[2] = byte(reasonCode)

		l.Extensions[0] = ext

		list = append(list, l)
	}

	return list, nil
}

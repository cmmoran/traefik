package vaultpki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

func loadPEMFile(path string) (string, string, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", time.Time{}, err
	}
	certPEM, keyPEM, notAfter, err := splitPEM(data)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return certPEM, keyPEM, notAfter, nil
}

func writePEMFile(path, certPEM, keyPEM string) error {
	payload := append([]byte(certPEM), []byte("\n")...)
	payload = append(payload, []byte(keyPEM)...)
	return os.WriteFile(path, payload, 0o600)
}

func splitPEM(data []byte) (string, string, time.Time, error) {
	var certBlock, keyBlock *pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certBlock == nil {
				certBlock = block
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if keyBlock == nil {
				keyBlock = block
			}
		}
	}
	if certBlock == nil || keyBlock == nil {
		return "", "", time.Time{}, errors.New("invalid pem bundle")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(certBlock)), string(pem.EncodeToMemory(keyBlock)), cert.NotAfter, nil
}

func certValidity(certPEM string) (time.Time, time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, time.Time{}, errors.New("invalid cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return cert.NotBefore, cert.NotAfter, nil
}

func parseKeyPair(certPEM, keyPEM string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

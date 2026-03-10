package tls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertificateStoreGetCertificate_MainFirstSortsSANs(t *testing.T) {
	store := NewCertificateStore(nil)
	cert := &CertificateData{Hash: "test"}
	store.DynamicCerts.Set(map[string]*CertificateData{
		"example.com,a.example.com,b.example.com": cert,
	})

	domains := []string{"example.com", "b.example.com", "a.example.com"}
	got := store.GetCertificate(domains)

	require.Same(t, cert, got)
}

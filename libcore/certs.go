package libcore

import (
	"crypto/x509"
	"log"
)

// updateRootCACerts replaces the fallback root CA pool with the certificates
// from the external ca.pem, so that certificates pinned by the user are
// trusted by the whole process.
//
// Go >= 1.24 provides x509.SetFallbackRoots for exactly this; the old
// implementation linked crypto/x509.systemRoots with //go:linkname, which the
// Go 1.25 linker check (checklinkname) rejects.
func updateRootCACerts(pem []byte) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		log.Println("failed to append certificates from pem")
		return
	}
	x509.SetFallbackRoots(roots)
	log.Println("external ca.pem was loaded")
}

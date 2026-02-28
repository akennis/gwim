package cert

import (
	"crypto/tls"
	"fmt"

	"github.com/google/certtostore"
)

// GetWin32Cert retrieves a certificate from the Windows Local Machine store by subject string
// and returns a tls.Certificate using github.com/google/certtostore for lookup and signing.
func GetWin32Cert(subject string) (tls.Certificate, error) {
	// 1. Initialize certtostore WinCertStore to manage the certificate store access
	wcs, err := certtostore.OpenWinCertStoreWithOptions(certtostore.WinCertStoreOptions{
		CurrentUser: false, // LocalMachine
		StoreFlags:  certtostore.CertStoreReadOnly,
	})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to open certtostore: %v", err)
	}
	// NOTE: We DO NOT defer wcs.Close() here.
	// The store and provider must remain open for the certificate signer to function.

	// 2. Find Certificate and context by Common Name (Subject) using native library method
	cert, ctx, _, err := wcs.CertByCommonName(subject)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate with subject %q not found in LocalMachine: %v", subject, err)
	}
	// NOTE: We DO NOT defer FreeCertContext(ctx) here.
	// The context must remain alive so that the private key handle stays valid.

	// 3. Use certtostore to acquire the crypto.Signer for this certificate context
	signer, err := wcs.CertKey(ctx)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to acquire private key via certtostore: %v", err)
	}

	// 4. Get the raw DER bytes from the parsed certificate.
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
	}, nil
}

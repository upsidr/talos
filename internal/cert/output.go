package cert

import (
	"fmt"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"
)

// OutputFiles holds the paths to written certificate files.
type OutputFiles struct {
	CertPath string
	KeyPath  string
	P12Path  string // Empty if no passphrase was provided
}

// WriteOutputFiles writes the issued certificate and key to outDir.
// If passphrase is non-empty, a PKCS#12 bundle is also written.
func WriteOutputFiles(issued *IssuedCert, outDir string, passphrase string, identity string, version int) (OutputFiles, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return OutputFiles{}, fmt.Errorf("create output directory: %w", err)
	}

	base := fmt.Sprintf("%s-v%d", identity, version)

	certPath := filepath.Join(outDir, base+".crt")
	if err := os.WriteFile(certPath, issued.CertificatePEM, 0644); err != nil {
		return OutputFiles{}, fmt.Errorf("write certificate: %w", err)
	}

	keyPath := filepath.Join(outDir, base+".key")
	if err := os.WriteFile(keyPath, issued.PrivateKeyPEM, 0600); err != nil {
		return OutputFiles{}, fmt.Errorf("write private key: %w", err)
	}

	out := OutputFiles{
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	if passphrase != "" {
		p12Data, err := pkcs12.Modern.Encode(issued.PrivateKey, issued.Certificate, nil, passphrase)
		if err != nil {
			return OutputFiles{}, fmt.Errorf("encode PKCS#12: %w", err)
		}
		p12Path := filepath.Join(outDir, base+".p12")
		if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
			return OutputFiles{}, fmt.Errorf("write PKCS#12: %w", err)
		}
		out.P12Path = p12Path
	}

	return out, nil
}

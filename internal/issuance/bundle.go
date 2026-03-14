package issuance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"time"
)

// BundleContents holds the data to include in a certificate distribution bundle.
type BundleContents struct {
	Identity      string
	Version       int
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	CACertPEM      []byte
}

// BuildBundle creates a gzip-compressed tar archive containing the certificate,
// private key, and CA certificate. The archive is assembled entirely in memory.
func BuildBundle(bc BundleContents) ([]byte, error) {
	prefix := fmt.Sprintf("%s--v%d", bc.Identity, bc.Version)

	files := []struct {
		Name string
		Mode int64
		Data []byte
	}{
		{prefix + ".crt", 0644, bc.CertificatePEM},
		{prefix + ".key", 0600, bc.PrivateKeyPEM},
		{"ca.crt", 0644, bc.CACertPEM},
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	now := time.Now()
	for _, f := range files {
		hdr := &tar.Header{
			Name:    f.Name,
			Mode:    f.Mode,
			Size:    int64(len(f.Data)),
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header for %s: %w", f.Name, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, fmt.Errorf("write tar data for %s: %w", f.Name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

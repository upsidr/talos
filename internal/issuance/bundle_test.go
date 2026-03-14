package issuance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestBuildBundle(t *testing.T) {
	bc := BundleContents{
		Identity:       "johndoe@directory.upsidr.local",
		Version:        3,
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nfake-cert\n-----END CERTIFICATE-----\n"),
		PrivateKeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nfake-key\n-----END EC PRIVATE KEY-----\n"),
		CACertPEM:      []byte("-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n"),
	}

	data, err := BuildBundle(bc)
	if err != nil {
		t.Fatalf("BuildBundle() error = %v", err)
	}

	// Decompress and verify
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader() error = %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)

	type fileInfo struct {
		name    string
		mode    int64
		content string
	}

	want := []fileInfo{
		{"johndoe@directory.upsidr.local--v3.crt", 0644, string(bc.CertificatePEM)},
		{"johndoe@directory.upsidr.local--v3.key", 0600, string(bc.PrivateKeyPEM)},
		{"ca.crt", 0644, string(bc.CACertPEM)},
	}

	for i, expected := range want {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("file %d: tar.Next() error = %v", i, err)
		}
		if hdr.Name != expected.name {
			t.Errorf("file %d: name = %q, want %q", i, hdr.Name, expected.name)
		}
		if hdr.Mode != expected.mode {
			t.Errorf("file %d: mode = %04o, want %04o", i, hdr.Mode, expected.mode)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("file %d: read error = %v", i, err)
		}
		if string(content) != expected.content {
			t.Errorf("file %d: content = %q, want %q", i, string(content), expected.content)
		}
	}

	// Should be no more files
	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("expected EOF after 3 files, got %v", err)
	}
}

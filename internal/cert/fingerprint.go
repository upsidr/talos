package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// Fingerprint computes the SHA-256 fingerprint of an X.509 certificate
// in the format "SHA256:ab:cd:ef:...".
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return "SHA256:" + strings.Join(parts, ":")
}

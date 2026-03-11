package cert

import "crypto"

// Signer extends crypto.Signer with a Close method for resource cleanup
// (e.g., closing KMS connections).
type Signer interface {
	crypto.Signer
	Close() error
}

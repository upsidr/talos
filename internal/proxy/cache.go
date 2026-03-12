package proxy

import (
	"sync"
	"time"

	"github.com/upsidr/talos/internal/store"
)

type cacheEntry struct {
	status    store.CertificateStatus
	identity  string
	version   int
	expiresAt time.Time
}

// Cache is a TTL-based in-memory cache for certificate validity lookups.
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*cacheEntry // keyed by fingerprint SHA-256
	ttl        time.Duration
	maxEntries int
}

// NewCache creates a new certificate validity cache.
func NewCache(ttl time.Duration, maxEntries int) *Cache {
	c := &Cache{
		entries:    make(map[string]*cacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
	go c.cleanupLoop()
	return c
}

// Get retrieves a cached certificate status by fingerprint.
// Returns the entry and true if found and not expired, nil and false otherwise.
func (c *Cache) Get(fingerprint string) (store.CertificateStatus, string, int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[fingerprint]
	if !ok || time.Now().After(entry.expiresAt) {
		return "", "", 0, false
	}
	return entry.status, entry.identity, entry.version, true
}

// GetStatus retrieves only the certificate status by fingerprint.
// This is a lightweight lookup for periodic revocation re-checks.
func (c *Cache) GetStatus(fingerprint string) (store.CertificateStatus, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[fingerprint]
	if !ok || time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.status, true
}

// Put stores a certificate status in the cache.
func (c *Cache) Put(fingerprint string, status store.CertificateStatus, identity string, version int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at capacity, skip (cleanup goroutine will free space)
	if len(c.entries) >= c.maxEntries {
		if _, exists := c.entries[fingerprint]; !exists {
			return
		}
	}

	c.entries[fingerprint] = &cacheEntry{
		status:    status,
		identity:  identity,
		version:   version,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Invalidate removes a specific fingerprint from the cache.
func (c *Cache) Invalidate(fingerprint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, fingerprint)
}

// Flush removes all entries from the cache.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for fp, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, fp)
			}
		}
		c.mu.Unlock()
	}
}

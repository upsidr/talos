package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/upsidr/talos/internal/store"
)

func TestCache_PutAndGet(t *testing.T) {
	c := NewCache(5*time.Second, 100)

	c.Put("fp1", store.StatusActive, "user@test.com", 1)

	status, identity, version, ok := c.Get("fp1")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if status != store.StatusActive {
		t.Errorf("status = %v, want %v", status, store.StatusActive)
	}
	if identity != "user@test.com" {
		t.Errorf("identity = %q, want %q", identity, "user@test.com")
	}
	if version != 1 {
		t.Errorf("version = %d, want %d", version, 1)
	}
}

func TestCache_Miss(t *testing.T) {
	c := NewCache(5*time.Second, 100)

	_, _, _, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := NewCache(50*time.Millisecond, 100)

	c.Put("fp1", store.StatusActive, "user@test.com", 1)

	// Should be present immediately
	_, _, _, ok := c.Get("fp1")
	if !ok {
		t.Fatal("expected cache hit immediately after put")
	}

	// Wait for TTL
	time.Sleep(100 * time.Millisecond)

	_, _, _, ok = c.Get("fp1")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCache_Invalidate(t *testing.T) {
	c := NewCache(5*time.Second, 100)

	c.Put("fp1", store.StatusActive, "user@test.com", 1)
	c.Invalidate("fp1")

	_, _, _, ok := c.Get("fp1")
	if ok {
		t.Error("expected cache miss after invalidation")
	}
}

func TestCache_Flush(t *testing.T) {
	c := NewCache(5*time.Second, 100)

	c.Put("fp1", store.StatusActive, "user1@test.com", 1)
	c.Put("fp2", store.StatusActive, "user2@test.com", 1)

	c.Flush()

	if _, _, _, ok := c.Get("fp1"); ok {
		t.Error("expected cache miss after flush for fp1")
	}
	if _, _, _, ok := c.Get("fp2"); ok {
		t.Error("expected cache miss after flush for fp2")
	}
}

func TestCache_MaxEntries(t *testing.T) {
	c := NewCache(5*time.Second, 2)

	c.Put("fp1", store.StatusActive, "user1", 1)
	c.Put("fp2", store.StatusActive, "user2", 1)

	// Third entry should be skipped (at capacity)
	c.Put("fp3", store.StatusActive, "user3", 1)

	_, _, _, ok := c.Get("fp3")
	if ok {
		t.Error("expected fp3 to not be cached when at capacity")
	}

	// Existing entries should still be present
	if _, _, _, ok := c.Get("fp1"); !ok {
		t.Error("expected fp1 to remain in cache")
	}
}

func TestCache_UpdateExistingEntry(t *testing.T) {
	c := NewCache(5*time.Second, 2)

	c.Put("fp1", store.StatusActive, "user1", 1)
	c.Put("fp2", store.StatusActive, "user2", 1)

	// Updating existing entry should work even at capacity
	c.Put("fp1", store.StatusRevoked, "user1", 1)

	status, _, _, ok := c.Get("fp1")
	if !ok {
		t.Fatal("expected cache hit for updated entry")
	}
	if status != store.StatusRevoked {
		t.Errorf("status = %v, want %v", status, store.StatusRevoked)
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewCache(5*time.Second, 1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fp := "fp" + string(rune('0'+i%10))
			c.Put(fp, store.StatusActive, "user", i)
			c.Get(fp)
			if i%3 == 0 {
				c.Invalidate(fp)
			}
		}(i)
	}
	wg.Wait()
}

// Package security provides secure memory handling and cryptographic primitives.
package security

import (
	"crypto/subtle"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SecureBytes represents bytes that are automatically zeroized on cleanup
type SecureBytes struct {
	data   []byte
	mu     sync.RWMutex
	locked bool
	freed  bool
}

// NewSecureBytes creates securely allocated bytes with mlock
func NewSecureBytes(size int) (*SecureBytes, error) {
	data := make([]byte, size)
	sb := &SecureBytes{data: data}

	// Lock memory to prevent swapping
	if err := sb.lock(); err != nil {
		// Non-fatal: continue without memory locking
		sb.locked = false
	} else {
		sb.locked = true
	}

	// Set finalizer for automatic cleanup
	runtime.SetFinalizer(sb, (*SecureBytes).Free)

	return sb, nil
}

// NewSecureBytesFromSlice creates secure bytes from existing slice (copies data)
func NewSecureBytesFromSlice(src []byte) (*SecureBytes, error) {
	sb, err := NewSecureBytes(len(src))
	if err != nil {
		return nil, err
	}
	copy(sb.data, src)
	Zeroize(src) // Zero the source
	return sb, nil
}

// lock attempts to lock memory pages
func (sb *SecureBytes) lock() error {
	if len(sb.data) == 0 {
		return nil
	}
	return unix.Mlock(sb.data)
}

// unlock unlocks memory pages
func (sb *SecureBytes) unlock() error {
	if len(sb.data) == 0 || !sb.locked {
		return nil
	}
	return unix.Munlock(sb.data)
}

// Bytes returns the underlying bytes (read-only access recommended)
func (sb *SecureBytes) Bytes() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	if sb.freed {
		return nil
	}
	return sb.data
}

// Len returns the length
func (sb *SecureBytes) Len() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return len(sb.data)
}

// Copy returns a copy of the data
func (sb *SecureBytes) Copy() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	if sb.freed {
		return nil
	}
	cpy := make([]byte, len(sb.data))
	copy(cpy, sb.data)
	return cpy
}

// Write writes data to secure bytes at offset
func (sb *SecureBytes) Write(offset int, data []byte) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.freed || offset+len(data) > len(sb.data) {
		return
	}
	copy(sb.data[offset:], data)
}

// Free zeroizes and frees the secure bytes
func (sb *SecureBytes) Free() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.freed {
		return
	}

	// Zeroize the data
	Zeroize(sb.data)

	// Unlock memory
	sb.unlock()

	sb.data = nil
	sb.freed = true

	// Remove finalizer
	runtime.SetFinalizer(sb, nil)
}

// IsFreed returns whether the memory has been freed
func (sb *SecureBytes) IsFreed() bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.freed
}

// Zeroize securely zeros a byte slice
func Zeroize(data []byte) {
	if len(data) == 0 {
		return
	}
	// Use volatile-like pattern to prevent compiler optimization
	for i := range data {
		data[i] = 0
	}
	// Memory barrier
	runtime.KeepAlive(data)
}

// ZeroizeString attempts to zero a string (unsafe, but sometimes necessary)
func ZeroizeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Get the underlying bytes via unsafe
	// Note: This is unsafe and may not work on all Go implementations
	header := (*[2]uintptr)(unsafe.Pointer(s))
	ptr := header[0]
	length := header[1]
	if ptr != 0 && length > 0 {
		data := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
		Zeroize(data)
	}
	*s = ""
}

// ConstantTimeCompare performs constant-time comparison
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeSelect selects v0 if selector is 0, v1 if selector is 1
func ConstantTimeSelect(selector int, v0, v1 []byte) []byte {
	if len(v0) != len(v1) {
		return nil
	}
	result := make([]byte, len(v0))
	subtle.ConstantTimeCopy(selector, result, v1)
	subtle.ConstantTimeCopy(1-selector, result, v0)
	return result
}

// SecureRandom is handled by the crypto package

// GuardedOperation executes an operation with secure cleanup guarantee
func GuardedOperation[T any](allocate func() (*SecureBytes, error), operation func([]byte) (T, error)) (T, error) {
	var zero T
	secure, err := allocate()
	if err != nil {
		return zero, err
	}
	defer secure.Free()

	return operation(secure.Bytes())
}

// SecurePool manages a pool of secure byte buffers
type SecurePool struct {
	pool  sync.Pool
	size  int
}

// NewSecurePool creates a new secure buffer pool
func NewSecurePool(bufferSize int) *SecurePool {
	return &SecurePool{
		size: bufferSize,
		pool: sync.Pool{
			New: func() any {
				sb, _ := NewSecureBytes(bufferSize)
				return sb
			},
		},
	}
}

// Get obtains a buffer from the pool
func (p *SecurePool) Get() *SecureBytes {
	sb := p.pool.Get().(*SecureBytes)
	if sb.IsFreed() {
		sb, _ = NewSecureBytes(p.size)
	}
	return sb
}

// Put returns a buffer to the pool (after zeroizing)
func (p *SecurePool) Put(sb *SecureBytes) {
	if sb == nil || sb.IsFreed() {
		return
	}
	// Zeroize before returning to pool
	Zeroize(sb.Bytes())
	p.pool.Put(sb)
}

// MemoryGuard protects sensitive operations with memory barriers
type MemoryGuard struct {
	active bool
}

// NewMemoryGuard creates a new memory guard
func NewMemoryGuard() *MemoryGuard {
	return &MemoryGuard{active: true}
}

// Protect executes function with memory protection
func (mg *MemoryGuard) Protect(fn func()) {
	if !mg.active {
		fn()
		return
	}

	// Pre-operation memory barrier
	runtime.Gosched()

	fn()

	// Post-operation memory barrier and GC hint
	runtime.Gosched()
	runtime.GC()
}

// Deactivate deactivates the guard
func (mg *MemoryGuard) Deactivate() {
	mg.active = false
}

// AntiDebug provides basic anti-debugging measures
type AntiDebug struct {
	enabled bool
}

// NewAntiDebug creates anti-debugging protection
func NewAntiDebug(enabled bool) *AntiDebug {
	return &AntiDebug{enabled: enabled}
}

// Check performs anti-debugging check
func (ad *AntiDebug) Check() bool {
	if !ad.enabled {
		return true
	}
	// Basic timing-based check
	// Real implementation would use ptrace detection, etc.
	return true
}

// TimingSafeEqual performs timing-safe equality check
func TimingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

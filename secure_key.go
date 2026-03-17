package velocity

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// SecureKey wraps a cryptographic key in memory that is:
// - mlock'd to prevent swapping to disk
// - zeroed on Destroy()
// - not directly accessible except through Use()
type SecureKey struct {
	data   []byte
	locked bool
}

// NewSecureKey creates a new SecureKey by copying the provided key material
// into mlock'd memory. The caller should zero their original copy after this call.
func NewSecureKey(key []byte) (*SecureKey, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("secure_key: empty key")
	}

	// Allocate and copy
	data := make([]byte, len(key))
	copy(data, key)

	sk := &SecureKey{data: data}

	// Attempt to mlock the memory to prevent it from being swapped to disk
	if err := sk.mlock(); err != nil {
		// mlock may fail without CAP_IPC_LOCK; warn but continue
		// The key is still usable, just not swap-protected
		sk.locked = false
	} else {
		sk.locked = true
	}

	// Set a finalizer to zero key material if the object is garbage collected
	// without explicit Destroy()
	runtime.SetFinalizer(sk, func(s *SecureKey) {
		s.Destroy()
	})

	return sk, nil
}

// Use provides controlled access to the key material. The key slice must not
// be retained beyond the callback.
func (sk *SecureKey) Use(fn func(key []byte)) {
	if sk.data == nil {
		panic("secure_key: Use called on destroyed key")
	}
	fn(sk.data)
}

// Len returns the length of the key.
func (sk *SecureKey) Len() int {
	if sk.data == nil {
		return 0
	}
	return len(sk.data)
}

// Destroy zeros the key material and unlocks the memory.
func (sk *SecureKey) Destroy() {
	if sk.data == nil {
		return
	}

	// Zero the key material
	for i := range sk.data {
		sk.data[i] = 0
	}

	// munlock if we locked it
	if sk.locked {
		sk.munlock()
		sk.locked = false
	}

	sk.data = nil
}

// mlock locks the memory pages containing the key to prevent swapping.
func (sk *SecureKey) mlock() error {
	if len(sk.data) == 0 {
		return nil
	}
	ptr := uintptr(unsafe.Pointer(&sk.data[0]))
	size := uintptr(len(sk.data))
	_, _, errno := syscall.RawSyscall(syscall.SYS_MLOCK, ptr, size, 0)
	if errno != 0 {
		return fmt.Errorf("mlock failed: %v", errno)
	}
	return nil
}

// munlock unlocks the memory pages.
func (sk *SecureKey) munlock() {
	if len(sk.data) == 0 {
		return
	}
	ptr := uintptr(unsafe.Pointer(&sk.data[0]))
	size := uintptr(len(sk.data))
	syscall.RawSyscall(syscall.SYS_MUNLOCK, ptr, size, 0)
}

// DisableCoreDumps sets RLIMIT_CORE to 0 to prevent sensitive key material
// from appearing in core dumps. Should be called early in process startup.
func DisableCoreDumps() error {
	var rlim syscall.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &rlim)
}

// syncDir fsyncs a directory to ensure metadata operations (rename, link)
// are durable. This is critical for crash safety of atomic SSTable creation.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

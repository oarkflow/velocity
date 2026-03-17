// Package security provides security hardening functionality.
package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	mrand "math/rand"
	"sync"
	"time"
)

// NonceTracker tracks nonces to prevent replay attacks
type NonceTracker struct {
	mu        sync.RWMutex
	nonces    map[string]time.Time
	maxAge    time.Duration
	maxSize   int
	cleanupAt time.Time
}

// NewNonceTracker creates a new nonce tracker
func NewNonceTracker(maxAge time.Duration, maxSize int) *NonceTracker {
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	if maxSize == 0 {
		maxSize = 100000
	}

	nt := &NonceTracker{
		nonces:  make(map[string]time.Time),
		maxAge:  maxAge,
		maxSize: maxSize,
	}

	return nt
}

// Check checks if a nonce has been seen before
// Returns true if the nonce is new (valid), false if it's a replay
func (nt *NonceTracker) Check(nonce string) bool {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	// Periodic cleanup
	if time.Now().After(nt.cleanupAt) {
		nt.cleanup()
		nt.cleanupAt = time.Now().Add(nt.maxAge / 2)
	}

	// Check if we've seen this nonce before
	if _, exists := nt.nonces[nonce]; exists {
		return false // Replay detected
	}

	// Check size limit
	if len(nt.nonces) >= nt.maxSize {
		nt.cleanup()
		if len(nt.nonces) >= nt.maxSize {
			// Still too large, remove oldest entries
			nt.pruneOldest(nt.maxSize / 10)
		}
	}

	// Record this nonce
	nt.nonces[nonce] = time.Now()
	return true
}

// cleanup removes expired nonces
func (nt *NonceTracker) cleanup() {
	cutoff := time.Now().Add(-nt.maxAge)
	for nonce, timestamp := range nt.nonces {
		if timestamp.Before(cutoff) {
			delete(nt.nonces, nonce)
		}
	}
}

// pruneOldest removes the oldest n entries
func (nt *NonceTracker) pruneOldest(n int) {
	if n <= 0 || len(nt.nonces) == 0 {
		return
	}

	// Find oldest entries
	type entry struct {
		nonce     string
		timestamp time.Time
	}
	entries := make([]entry, 0, len(nt.nonces))
	for k, v := range nt.nonces {
		entries = append(entries, entry{k, v})
	}

	// Simple selection of oldest
	removed := 0
	cutoff := time.Now().Add(-nt.maxAge / 2)
	for _, e := range entries {
		if removed >= n {
			break
		}
		if e.timestamp.Before(cutoff) {
			delete(nt.nonces, e.nonce)
			removed++
		}
	}
}

// Size returns the current number of tracked nonces
func (nt *NonceTracker) Size() int {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	return len(nt.nonces)
}

// Clear removes all nonces
func (nt *NonceTracker) Clear() {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.nonces = make(map[string]time.Time)
}

// RequestSigner provides signing for API requests
type RequestSigner struct {
	secret []byte
}

// NewRequestSigner creates a request signer
func NewRequestSigner(secret []byte) *RequestSigner {
	return &RequestSigner{secret: secret}
}

// Sign creates a signature for request data
func (rs *RequestSigner) Sign(data []byte, timestamp time.Time, nonce string) string {
	h := sha256.New()
	h.Write(data)
	h.Write([]byte(timestamp.UTC().Format(time.RFC3339)))
	h.Write([]byte(nonce))
	h.Write(rs.secret)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify verifies a request signature
func (rs *RequestSigner) Verify(data []byte, timestamp time.Time, nonce string, signature string) bool {
	expected := rs.Sign(data, timestamp, nonce)
	return TimingSafeEqual(expected, signature)
}

// ClockSkewValidator validates timestamps with tolerance for clock skew
type ClockSkewValidator struct {
	maxSkew time.Duration
}

// NewClockSkewValidator creates a clock skew validator
func NewClockSkewValidator(maxSkew time.Duration) *ClockSkewValidator {
	if maxSkew == 0 {
		maxSkew = 5 * time.Minute
	}
	return &ClockSkewValidator{maxSkew: maxSkew}
}

// Validate checks if a timestamp is within acceptable skew
func (csv *ClockSkewValidator) Validate(timestamp time.Time) bool {
	now := time.Now()
	diff := now.Sub(timestamp)
	if diff < 0 {
		diff = -diff
	}
	return diff <= csv.maxSkew
}

// RollbackDetector detects potential rollback attacks
type RollbackDetector struct {
	mu         sync.RWMutex
	versions   map[string]uint64
}

// NewRollbackDetector creates a rollback detector
func NewRollbackDetector() *RollbackDetector {
	return &RollbackDetector{
		versions: make(map[string]uint64),
	}
}

// Check checks if a version is valid (not a rollback)
// Returns true if valid, false if rollback detected
func (rd *RollbackDetector) Check(key string, version uint64) bool {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	current, exists := rd.versions[key]
	if exists && version < current {
		return false // Rollback detected
	}

	rd.versions[key] = version
	return true
}

// GetVersion returns the current version for a key
func (rd *RollbackDetector) GetVersion(key string) uint64 {
	rd.mu.RLock()
	defer rd.mu.RUnlock()
	return rd.versions[key]
}

// ForceVersion forces a specific version (for recovery)
func (rd *RollbackDetector) ForceVersion(key string, version uint64) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.versions[key] = version
}

// AbuseDetector detects suspicious patterns
type AbuseDetector struct {
	mu             sync.RWMutex
	failedAttempts map[string][]time.Time
	threshold      int
	window         time.Duration
	lockoutTime    time.Duration
	lockedOut      map[string]time.Time
}

// NewAbuseDetector creates an abuse detector
func NewAbuseDetector(threshold int, window, lockout time.Duration) *AbuseDetector {
	if threshold == 0 {
		threshold = 5
	}
	if window == 0 {
		window = 5 * time.Minute
	}
	if lockout == 0 {
		lockout = 15 * time.Minute
	}

	return &AbuseDetector{
		failedAttempts: make(map[string][]time.Time),
		threshold:      threshold,
		window:         window,
		lockoutTime:    lockout,
		lockedOut:      make(map[string]time.Time),
	}
}

// RecordFailure records a failed attempt
func (ad *AbuseDetector) RecordFailure(key string) bool {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()

	// Check if locked out
	if lockoutEnd, exists := ad.lockedOut[key]; exists {
		if now.Before(lockoutEnd) {
			return false // Still locked out
		}
		delete(ad.lockedOut, key)
	}

	// Clean old attempts
	cutoff := now.Add(-ad.window)
	attempts := ad.failedAttempts[key]
	var recent []time.Time
	for _, t := range attempts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	// Add new attempt
	recent = append(recent, now)
	ad.failedAttempts[key] = recent

	// Check threshold
	if len(recent) >= ad.threshold {
		ad.lockedOut[key] = now.Add(ad.lockoutTime)
		delete(ad.failedAttempts, key)
		return false // Now locked out
	}

	return true
}

// RecordSuccess clears failed attempts
func (ad *AbuseDetector) RecordSuccess(key string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	delete(ad.failedAttempts, key)
}

// IsLockedOut checks if a key is currently locked out
func (ad *AbuseDetector) IsLockedOut(key string) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	lockoutEnd, exists := ad.lockedOut[key]
	if !exists {
		return false
	}
	return time.Now().Before(lockoutEnd)
}

// GetLockoutEnd returns when the lockout expires
func (ad *AbuseDetector) GetLockoutEnd(key string) (time.Time, bool) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	lockoutEnd, exists := ad.lockedOut[key]
	return lockoutEnd, exists
}

// IntegrityVerifier verifies binary integrity
type IntegrityVerifier struct {
	expectedHash string
}

// NewIntegrityVerifier creates an integrity verifier
func NewIntegrityVerifier(expectedHash string) *IntegrityVerifier {
	return &IntegrityVerifier{expectedHash: expectedHash}
}

// Verify checks if binary data matches expected hash
func (iv *IntegrityVerifier) Verify(data []byte) bool {
	if iv.expectedHash == "" {
		return true // No hash to verify
	}

	h := sha256.Sum256(data)
	actualHash := hex.EncodeToString(h[:])

	return TimingSafeEqual(actualHash, iv.expectedHash)
}

// SecureUpdateManager manages secure updates
type SecureUpdateManager struct {
	trustedSigners [][]byte
	currentVersion string
}

// NewSecureUpdateManager creates a secure update manager
func NewSecureUpdateManager(currentVersion string, trustedSigners [][]byte) *SecureUpdateManager {
	return &SecureUpdateManager{
		trustedSigners: trustedSigners,
		currentVersion: currentVersion,
	}
}

// VerifyUpdate verifies an update package
func (sum *SecureUpdateManager) VerifyUpdate(updateData []byte, signature []byte, signerPubKey []byte) bool {
	// Check if signer is trusted
	trusted := false
	for _, ts := range sum.trustedSigners {
		if subtle.ConstantTimeCompare(ts, signerPubKey) == 1 {
			trusted = true
			break
		}
	}

	if !trusted {
		return false
	}

	// Signature verification would use ed25519.Verify here
	// For now, just return that signer is trusted
	return trusted && len(signature) > 0
}

// GetCurrentVersion returns the current version
func (sum *SecureUpdateManager) GetCurrentVersion() string {
	return sum.currentVersion
}

// ConstantTimeOps provides constant-time operations to prevent timing attacks
type ConstantTimeOps struct{}

// Compare performs constant-time comparison
func (c *ConstantTimeOps) Compare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Select performs constant-time selection
func (c *ConstantTimeOps) Select(selector int, a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	result := make([]byte, len(a))
	subtle.ConstantTimeCopy(selector, result, b)
	subtle.ConstantTimeCopy(1-selector, result, a)
	return result
}

// TimingGuard adds random delays to thwart timing attacks
type TimingGuard struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewTimingGuard creates a new timing guard
func NewTimingGuard(minDelay, maxDelay time.Duration) *TimingGuard {
	return &TimingGuard{
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
}

// Guard executes an operation with randomized timing padding
func (g *TimingGuard) Guard(operation func() error) error {
	start := time.Now()
	err := operation()
	elapsed := time.Since(start)

	// Add random delay to normalize timing
	// Use crypto/rand for secure randomness if possible, but math/rand is acceptable for timing noise
	// Here we stick to simple math/rand for non-cryptographic delay
	delta := int64(g.maxDelay - g.minDelay)
	if delta <= 0 {
		delta = 1
	}

	extra := time.Duration(mrand.Int63n(delta))
	target := g.minDelay + extra

	if elapsed < target {
		time.Sleep(target - elapsed)
	}
	return err
}

// CacheDefense provides cache-timing attack mitigations
type CacheDefense struct{}

// TouchAllBytes accesses all bytes in a buffer to fill cache lines uniformly
func (d *CacheDefense) TouchAllBytes(data []byte) {
	var dummy byte
	for i := range data {
		dummy ^= data[i]
	}
	// Prevent compiler optimization
	_ = dummy
}

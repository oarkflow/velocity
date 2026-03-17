package velocity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// MFAProvider interface for multi-factor authentication
type MFAProvider interface {
	GenerateSecret(userID string) (secret string, qrCode []byte, error error)
	ValidateTOTP(userID, token string) error
	ValidateBackupCode(userID, code string) error
}

// MFAManager manages multi-factor authentication
type MFAManager struct {
	db            *DB
	totpConfig    *TOTPConfig
	hotpConfig    *HOTPConfig
	backupCodes   map[string][]string // userID -> codes
}

// TOTPConfig configures Time-based One-Time Password
type TOTPConfig struct {
	Issuer      string        `json:"issuer"` // "Velocity Database"
	Algorithm   string        `json:"algorithm"` // SHA1, SHA256, SHA512
	Digits      int           `json:"digits"` // 6 or 8
	Period      int           `json:"period"` // 30 seconds
	Skew        int           `json:"skew"` // Allow +/- N periods (default: 1)
}

// HOTPConfig configures HMAC-based One-Time Password
type HOTPConfig struct {
	Issuer    string `json:"issuer"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Counter   uint64 `json:"counter"`
}

// NewMFAManager creates a new MFA manager
func NewMFAManager(db *DB) *MFAManager {
	return &MFAManager{
		db: db,
		totpConfig: &TOTPConfig{
			Issuer:    "Velocity Database",
			Algorithm: "SHA1", // Standard for compatibility
			Digits:    6,
			Period:    30,
			Skew:      1,
		},
		hotpConfig: &HOTPConfig{
			Issuer:    "Velocity Database",
			Algorithm: "SHA1",
			Digits:    6,
			Counter:   0,
		},
		backupCodes: make(map[string][]string),
	}
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (mfa *MFAManager) GenerateTOTPSecret(userID, accountName string) (*TOTPSetup, error) {
	// Generate random secret (160 bits / 20 bytes recommended)
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Encode as base32 (required for TOTP)
	secretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	// Generate backup codes
	backupCodes, err := mfa.generateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes
	mfa.backupCodes[userID] = backupCodes

	// Generate provisioning URI for QR code
	// Format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		mfa.totpConfig.Issuer,
		accountName,
		secretBase32,
		mfa.totpConfig.Issuer,
		mfa.totpConfig.Algorithm,
		mfa.totpConfig.Digits,
		mfa.totpConfig.Period,
	)

	setup := &TOTPSetup{
		Secret:      secretBase32,
		QRCodeURI:   uri,
		BackupCodes: backupCodes,
		Algorithm:   mfa.totpConfig.Algorithm,
		Digits:      mfa.totpConfig.Digits,
		Period:      mfa.totpConfig.Period,
	}

	return setup, nil
}

// TOTPSetup contains TOTP setup information
type TOTPSetup struct {
	Secret      string   `json:"secret"`
	QRCodeURI   string   `json:"qr_code_uri"`
	BackupCodes []string `json:"backup_codes"`
	Algorithm   string   `json:"algorithm"`
	Digits      int      `json:"digits"`
	Period      int      `json:"period"`
}

// ValidateTOTP validates a TOTP token
func (mfa *MFAManager) ValidateTOTP(secret, token string) (bool, error) {
	if len(token) != mfa.totpConfig.Digits {
		return false, errors.New("invalid token length")
	}

	// Decode base32 secret
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false, fmt.Errorf("invalid secret: %w", err)
	}

	// Get current time counter
	currentCounter := time.Now().Unix() / int64(mfa.totpConfig.Period)

	// Check token with skew (allow +/- N periods for clock drift)
	for i := -mfa.totpConfig.Skew; i <= mfa.totpConfig.Skew; i++ {
		counter := currentCounter + int64(i)
		expectedToken := mfa.generateTOTP(secretBytes, counter)
		if token == expectedToken {
			return true, nil
		}
	}

	return false, nil
}

// generateTOTP generates a TOTP token
func (mfa *MFAManager) generateTOTP(secret []byte, counter int64) string {
	// Convert counter to 8-byte big-endian
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))

	// Generate HMAC
	var h hash.Hash
	switch mfa.totpConfig.Algorithm {
	case "SHA1":
		h = hmac.New(sha1.New, secret)
	case "SHA256":
		h = hmac.New(sha256.New, secret)
	case "SHA512":
		h = hmac.New(sha512.New, secret)
	default:
		h = hmac.New(sha1.New, secret)
	}

	h.Write(counterBytes)
	hmacResult := h.Sum(nil)

	// Dynamic truncation (RFC 4226)
	offset := hmacResult[len(hmacResult)-1] & 0x0F
	code := binary.BigEndian.Uint32(hmacResult[offset:offset+4]) & 0x7FFFFFFF

	// Generate N-digit code
	divisor := uint32(1)
	for i := 0; i < mfa.totpConfig.Digits; i++ {
		divisor *= 10
	}
	code = code % divisor

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", mfa.totpConfig.Digits)
	return fmt.Sprintf(format, code)
}

// ValidateHOTP validates an HMAC-based OTP
func (mfa *MFAManager) ValidateHOTP(secret string, token string, counter uint64) (bool, error) {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false, fmt.Errorf("invalid secret: %w", err)
	}

	// Check token with look-ahead window (account for missed codes)
	for i := uint64(0); i < 10; i++ {
		expectedToken := mfa.generateHOTP(secretBytes, counter+i)
		if token == expectedToken {
			return true, nil
		}
	}

	return false, nil
}

// generateHOTP generates an HOTP token
func (mfa *MFAManager) generateHOTP(secret []byte, counter uint64) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	var h hash.Hash
	switch mfa.hotpConfig.Algorithm {
	case "SHA1":
		h = hmac.New(sha1.New, secret)
	case "SHA256":
		h = hmac.New(sha256.New, secret)
	case "SHA512":
		h = hmac.New(sha512.New, secret)
	default:
		h = hmac.New(sha1.New, secret)
	}

	h.Write(counterBytes)
	hmacResult := h.Sum(nil)

	offset := hmacResult[len(hmacResult)-1] & 0x0F
	code := binary.BigEndian.Uint32(hmacResult[offset:offset+4]) & 0x7FFFFFFF

	divisor := uint32(1)
	for i := 0; i < mfa.hotpConfig.Digits; i++ {
		divisor *= 10
	}
	code = code % divisor

	format := fmt.Sprintf("%%0%dd", mfa.hotpConfig.Digits)
	return fmt.Sprintf(format, code)
}

// generateBackupCodes generates one-time backup codes
func (mfa *MFAManager) generateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 8-character alphanumeric code
		codeBytes := make([]byte, 6)
		if _, err := rand.Read(codeBytes); err != nil {
			return nil, err
		}

		// Convert to alphanumeric (base36-like)
		code := strings.ToUpper(fmt.Sprintf("%X", codeBytes))
		if len(code) > 8 {
			code = code[:8]
		}

		// Format as XXXX-XXXX
		if len(code) >= 8 {
			codes[i] = code[:4] + "-" + code[4:8]
		} else {
			codes[i] = code
		}
	}

	return codes, nil
}

// ValidateBackupCode validates and consumes a backup code
func (mfa *MFAManager) ValidateBackupCode(userID, code string) (bool, error) {
	codes, exists := mfa.backupCodes[userID]
	if !exists {
		return false, errors.New("no backup codes found for user")
	}

	// Check if code matches
	for i, backupCode := range codes {
		if backupCode == code {
			// Remove used code
			mfa.backupCodes[userID] = append(codes[:i], codes[i+1:]...)
			return true, nil
		}
	}

	return false, nil
}

// MFAEnrollment represents a user's MFA enrollment
type MFAEnrollment struct {
	UserID        string    `json:"user_id"`
	Enabled       bool      `json:"enabled"`
	TOTPSecret    string    `json:"totp_secret,omitempty"`
	BackupCodes   []string  `json:"backup_codes,omitempty"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	LastUsed      time.Time `json:"last_used,omitempty"`
	FailedAttempts int      `json:"failed_attempts"`
}

// EnrollUser enrolls a user in MFA
func (mfa *MFAManager) EnrollUser(userID, accountName string) (*MFAEnrollment, error) {
	setup, err := mfa.GenerateTOTPSecret(userID, accountName)
	if err != nil {
		return nil, err
	}

	enrollment := &MFAEnrollment{
		UserID:      userID,
		Enabled:     false, // Require verification before enabling
		TOTPSecret:  setup.Secret,
		BackupCodes: setup.BackupCodes,
		EnrolledAt:  time.Now(),
	}

	return enrollment, nil
}

// VerifyEnrollment verifies and activates MFA for a user
func (mfa *MFAManager) VerifyEnrollment(enrollment *MFAEnrollment, token string) error {
	valid, err := mfa.ValidateTOTP(enrollment.TOTPSecret, token)
	if err != nil {
		return err
	}

	if !valid {
		return errors.New("invalid verification token")
	}

	enrollment.Enabled = true
	enrollment.LastUsed = time.Now()

	return nil
}

// AuthenticateWithMFA authenticates a user with MFA
func (mfa *MFAManager) AuthenticateWithMFA(enrollment *MFAEnrollment, token string) error {
	if !enrollment.Enabled {
		return errors.New("MFA not enabled for user")
	}

	// Try TOTP first
	valid, err := mfa.ValidateTOTP(enrollment.TOTPSecret, token)
	if err != nil {
		return err
	}

	if valid {
		enrollment.LastUsed = time.Now()
		enrollment.FailedAttempts = 0
		return nil
	}

	// Try backup code
	valid, err = mfa.ValidateBackupCode(enrollment.UserID, token)
	if err == nil && valid {
		enrollment.LastUsed = time.Now()
		enrollment.FailedAttempts = 0
		return nil
	}

	// Failed authentication
	enrollment.FailedAttempts++

	// Lock account after 5 failed attempts
	if enrollment.FailedAttempts >= 5 {
		return errors.New("too many failed attempts, account locked")
	}

	return errors.New("invalid MFA token")
}

// RegeneratBackupCodes generates new backup codes for a user
func (mfa *MFAManager) RegenerateBackupCodes(userID string) ([]string, error) {
	codes, err := mfa.generateBackupCodes(10)
	if err != nil {
		return nil, err
	}

	mfa.backupCodes[userID] = codes
	return codes, nil
}

// DisableMFA disables MFA for a user
func (mfa *MFAManager) DisableMFA(enrollment *MFAEnrollment) error {
	enrollment.Enabled = false
	enrollment.TOTPSecret = ""
	delete(mfa.backupCodes, enrollment.UserID)
	return nil
}

// GetMFAStatus returns MFA status for a user
func (mfa *MFAManager) GetMFAStatus(userID string) (*MFAStatus, error) {
	_, hasBackupCodes := mfa.backupCodes[userID]

	status := &MFAStatus{
		UserID:            userID,
		Enrolled:          hasBackupCodes,
		BackupCodesCount:  len(mfa.backupCodes[userID]),
	}

	return status, nil
}

// MFAStatus represents MFA status
type MFAStatus struct {
	UserID           string    `json:"user_id"`
	Enrolled         bool      `json:"enrolled"`
	Enabled          bool      `json:"enabled"`
	BackupCodesCount int       `json:"backup_codes_count"`
	LastUsed         time.Time `json:"last_used,omitempty"`
	FailedAttempts   int       `json:"failed_attempts"`
}

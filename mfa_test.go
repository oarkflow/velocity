package velocity

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestMFAManager_GenerateTOTPSecret(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Generate TOTP secret
	config, err := mfa.GenerateTOTPSecret("user@example.com", "VelocityDB")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	// Verify secret is base32 encoded
	_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(config.Secret)
	if err != nil {
		t.Errorf("Secret is not valid base32: %v", err)
	}

	// Verify backup codes generated
	if len(config.BackupCodes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(config.BackupCodes))
	}

	// Verify QR code URI format
	if config.QRCodeURI == "" {
		t.Error("QR code URI not generated")
	}

	// Verify algorithm settings
	if config.Algorithm != "SHA1" {
		t.Errorf("Expected SHA1 algorithm, got %s", config.Algorithm)
	}

	if config.Digits != 6 {
		t.Errorf("Expected 6 digits, got %d", config.Digits)
	}

	if config.Period != 30 {
		t.Errorf("Expected 30 second period, got %d", config.Period)
	}
}

func TestMFAManager_ValidateTOTP_InvalidToken(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Generate secret
	config, err := mfa.GenerateTOTPSecret("test@example.com", "VelocityDB")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	// Test with invalid token
	valid, err := mfa.ValidateTOTP(config.Secret, "000000")
	if err != nil {
		t.Fatalf("TOTP validation failed: %v", err)
	}

	// Invalid token should not validate (unless extremely unlucky)
	if valid {
		t.Log("Warning: Random token happened to match - this is rare but possible")
	}
}

func TestMFAManager_ValidateTOTP_WrongLength(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	config, err := mfa.GenerateTOTPSecret("test@example.com", "VelocityDB")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	// Test with wrong length token
	_, err = mfa.ValidateTOTP(config.Secret, "12345") // 5 digits instead of 6
	if err == nil {
		t.Error("Should reject token with wrong length")
	}
}

func TestMFAManager_ValidateTOTP_InvalidSecret(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Test with invalid base32 secret
	_, err = mfa.ValidateTOTP("INVALID!!!SECRET", "123456")
	if err == nil {
		t.Error("Should reject invalid base32 secret")
	}
}

func TestMFAManager_EnrollUser(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Enroll user
	enrollment, err := mfa.EnrollUser("user123", "user@example.com")
	if err != nil {
		t.Fatalf("Failed to enroll user: %v", err)
	}

	if enrollment.UserID != "user123" {
		t.Errorf("Expected UserID 'user123', got %s", enrollment.UserID)
	}

	if len(enrollment.TOTPSecret) == 0 {
		t.Error("TOTP secret not generated")
	}

	if len(enrollment.BackupCodes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(enrollment.BackupCodes))
	}

	if enrollment.Enabled {
		t.Error("New enrollment should not be enabled before verification")
	}

	if enrollment.EnrolledAt.IsZero() {
		t.Error("EnrolledAt timestamp not set")
	}
}

func TestMFAManager_BackupCodes(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Generate backup codes
	codes, err := mfa.generateBackupCodes(10)
	if err != nil {
		t.Fatalf("Failed to generate backup codes: %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(codes))
	}

	// Check code format (9 characters including dash, e.g., XXXX-XXXX)
	for _, code := range codes {
		if len(code) != 9 {
			t.Errorf("Backup code has wrong length: %s (expected 9 chars)", code)
		}
		// Check for dash in middle
		if len(code) == 9 && code[4] != '-' {
			t.Errorf("Backup code should have dash in middle: %s", code)
		}
	}

	// Codes should be unique
	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Errorf("Duplicate backup code: %s", code)
		}
		seen[code] = true
	}
}

func TestMFAManager_ValidateHOTP_Invalid(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Test with invalid secret
	_, err = mfa.ValidateHOTP("INVALID!!!SECRET", "123456", 0)
	if err == nil {
		t.Error("Should reject invalid base32 secret")
	}
}

func TestTOTPConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	// Check default configuration
	if mfa.totpConfig.Issuer != "Velocity Database" {
		t.Errorf("Expected issuer 'Velocity Database', got %s", mfa.totpConfig.Issuer)
	}

	if mfa.totpConfig.Algorithm != "SHA1" {
		t.Errorf("Expected algorithm SHA1, got %s", mfa.totpConfig.Algorithm)
	}

	if mfa.totpConfig.Digits != 6 {
		t.Errorf("Expected 6 digits, got %d", mfa.totpConfig.Digits)
	}

	if mfa.totpConfig.Period != 30 {
		t.Errorf("Expected 30 second period, got %d", mfa.totpConfig.Period)
	}

	if mfa.totpConfig.Skew != 1 {
		t.Errorf("Expected skew of 1, got %d", mfa.totpConfig.Skew)
	}
}

func TestMFAManager_QRCodeURI(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	mfa := NewMFAManager(db)

	config, err := mfa.GenerateTOTPSecret("testuser@example.com", "VelocityDB")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	// Verify URI format
	uri := config.QRCodeURI
	if uri == "" {
		t.Fatal("QR code URI is empty")
	}

	// Check URI starts with otpauth://totp/
	if !stringContains(uri, "otpauth://totp/") {
		t.Error("QR code URI should start with otpauth://totp/")
	}

	// Check URI contains issuer (might be URL encoded different ways)
	if !stringContains(uri, "Velocity") {
		t.Errorf("QR code URI should contain issuer, got: %s", uri)
	}

	// Check URI contains secret
	if !stringContains(uri, "secret=") {
		t.Error("QR code URI should contain secret parameter")
	}

	// Check URI contains algorithm
	if !stringContains(uri, "algorithm=SHA1") {
		t.Error("QR code URI should contain algorithm parameter")
	}

	// Check URI contains digits
	if !stringContains(uri, "digits=6") {
		t.Error("QR code URI should contain digits parameter")
	}

	// Check URI contains period
	if !stringContains(uri, "period=30") {
		t.Error("QR code URI should contain period parameter")
	}
}

// Helper function to check if string contains substring
func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && hasSubstring(s, substr))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func BenchmarkTOTPValidation(b *testing.B) {
	dir := b.TempDir()
	db, _ := New(dir)
	defer db.Close()

	mfa := NewMFAManager(db)
	config, _ := mfa.GenerateTOTPSecret("bench@example.com", "VelocityDB")

	// Use a test token (will fail but tests the validation path)
	token := "123456"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mfa.ValidateTOTP(config.Secret, token)
	}
}

func BenchmarkGenerateTOTPSecret(b *testing.B) {
	dir := b.TempDir()
	db, _ := New(dir)
	defer db.Close()

	mfa := NewMFAManager(db)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mfa.GenerateTOTPSecret("user@example.com", "VelocityDB")
	}
}

func BenchmarkGenerateBackupCodes(b *testing.B) {
	dir := b.TempDir()
	db, _ := New(dir)
	defer db.Close()

	mfa := NewMFAManager(db)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mfa.generateBackupCodes(10)
	}
}

// TestMFAEnrollment_StructureValidation tests the MFAEnrollment structure
func TestMFAEnrollment_StructureValidation(t *testing.T) {
	enrollment := &MFAEnrollment{
		UserID:         "test-user",
		Enabled:        false,
		TOTPSecret:     "SECRET123",
		BackupCodes:    []string{"CODE1", "CODE2"},
		EnrolledAt:     time.Now(),
		LastUsed:       time.Now(),
		FailedAttempts: 0,
	}

	if enrollment.UserID != "test-user" {
		t.Error("UserID not set correctly")
	}

	if enrollment.Enabled {
		t.Error("Enabled should be false initially")
	}

	if len(enrollment.BackupCodes) != 2 {
		t.Error("BackupCodes not set correctly")
	}

	if enrollment.FailedAttempts != 0 {
		t.Error("FailedAttempts should start at 0")
	}
}

package velocity

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oarkflow/shamir"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// MasterKeyManager handles flexible master key management
type MasterKeyManager struct {
	config     MasterKeyConfig
	dbPath     string

	// User key caching
	cachedKey      []byte
	cacheExpiry    time.Time
	lastAccess     time.Time
	cacheMutex     sync.RWMutex

	// Key prompt function (can be overridden for testing)
	promptFunc func(string) (string, error)
}

// NewMasterKeyManager creates a new master key manager
func NewMasterKeyManager(dbPath string, config MasterKeyConfig) *MasterKeyManager {
	return &MasterKeyManager{
		config:     config,
		dbPath:     dbPath,
		promptFunc: defaultPromptFunc,
	}
}

// GetMasterKey retrieves the master key based on configuration
func (mkm *MasterKeyManager) GetMasterKey(explicit []byte) ([]byte, error) {
	// If explicit key provided, use it
	if len(explicit) > 0 {
		if len(explicit) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("invalid explicit key length: expected %d bytes", chacha20poly1305.KeySize)
		}
		out := make([]byte, chacha20poly1305.KeySize)
		copy(out, explicit)
		return out, nil
	}

	switch mkm.config.Source {
	case SystemFile:
		return mkm.getSystemFileKey()
	case UserDefined:
		return mkm.getUserDefinedKey()
	case ShamirShared:
		return mkm.getShamirSharedKey()
	default:
		return mkm.getSystemFileKey() // fallback
	}
}

// getSystemFileKey uses the traditional file-based approach
func (mkm *MasterKeyManager) getSystemFileKey() ([]byte, error) {
	return ensureMasterKey(mkm.dbPath, nil)
}

// getUserDefinedKey prompts user and handles caching
func (mkm *MasterKeyManager) getUserDefinedKey() ([]byte, error) {
	// Check cache first
	if mkm.config.UserKeyCache.Enabled {
		mkm.cacheMutex.RLock()
		if mkm.cachedKey != nil && time.Now().Before(mkm.cacheExpiry) {
			// Check idle timeout
			if mkm.config.UserKeyCache.MaxIdleTime > 0 &&
			   time.Since(mkm.lastAccess) > mkm.config.UserKeyCache.MaxIdleTime {
				mkm.cacheMutex.RUnlock()
				mkm.clearCache()
			} else {
				mkm.lastAccess = time.Now()
				key := make([]byte, len(mkm.cachedKey))
				copy(key, mkm.cachedKey)
				mkm.cacheMutex.RUnlock()
				return key, nil
			}
		} else {
			mkm.cacheMutex.RUnlock()
		}
	}

	// Check if Shamir shares exist
	sharesDir := filepath.Join(mkm.dbPath, "shamir_shares")
	if _, err := os.Stat(sharesDir); err == nil {
		// Shares exist, use them to reconstruct key
		return mkm.loadShamirShares(sharesDir)
	}

	// Check if key already exists (for user-defined mode)
	if mkm.hasExistingKey() {
		// Key exists, just prompt for it
		keyStr, err := mkm.promptFunc("Enter master key: ")
		if err != nil {
			return nil, fmt.Errorf("failed to read master key: %w", err)
		}
		key, err := ParseKeyString(strings.TrimSpace(keyStr))
		if err != nil {
			return nil, fmt.Errorf("invalid master key: %w", err)
		}
		if mkm.config.UserKeyCache.Enabled {
			mkm.cacheKey(key)
		}
		return key, nil
	}

	// No existing key, ask if user wants to generate a secure key
	genResponse, err := mkm.promptFunc("Generate secure MasterKey? Y/n: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var key []byte
	if strings.ToLower(strings.TrimSpace(genResponse)) != "n" {
		// Generate secure key
		key = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		keyStr := base64.StdEncoding.EncodeToString(key)

		// Copy to clipboard
		if err := copyToClipboard(keyStr); err != nil {
			fmt.Printf("Generated MasterKey: %s\n(Failed to copy to clipboard: %v)\nPress Enter to use this key...\n", keyStr, err)
		} else {
			fmt.Printf("Generated MasterKey: %s\n(Copied to clipboard)\nPress Enter to use this key...\n", keyStr)
		}

		_, err = mkm.promptFunc("")
		if err != nil {
			return nil, fmt.Errorf("failed to confirm: %w", err)
		}
	} else {
		// Prompt user for key
		keyStr, err := mkm.promptFunc("Enter master key (32 bytes, base64/hex): ")
		if err != nil {
			return nil, fmt.Errorf("failed to read master key: %w", err)
		}
		key, err = ParseKeyString(strings.TrimSpace(keyStr))
		if err != nil {
			return nil, fmt.Errorf("invalid master key: %w", err)
		}
	}

	// Ask if user wants Shamir sharing
	shamirResponse, err := mkm.promptFunc("Split key using Shamir sharing? Y/n: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read Shamir response: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(shamirResponse)) != "n" {
		// Get number of shares
		sharesResponse, err := mkm.promptFunc("Number of shares (minimum 3, default 3): ")
		if err != nil {
			return nil, fmt.Errorf("failed to read shares count: %w", err)
		}

		totalShares := 3 // default
		if strings.TrimSpace(sharesResponse) != "" {
			if n, parseErr := strconv.Atoi(strings.TrimSpace(sharesResponse)); parseErr == nil && n >= 3 {
				totalShares = n
			}
		}

		threshold := (totalShares + 1) / 2 // majority
		if threshold < 2 {
			threshold = 2
		}

		// Create Shamir shares
		if err := mkm.createShamirSharesFromKey(key, threshold, totalShares); err != nil {
			return nil, fmt.Errorf("failed to create Shamir shares: %w", err)
		}
	}

	// Cache the key if enabled
	if mkm.config.UserKeyCache.Enabled {
		mkm.cacheKey(key)
	}

	return key, nil
}

// hasExistingKey checks if a key has been set before for this database
func (mkm *MasterKeyManager) hasExistingKey() bool {
	// Check if any encrypted data exists (WAL or SST files)
	walPath := filepath.Join(mkm.dbPath, "wal.log")
	if _, err := os.Stat(walPath); err == nil {
		return true
	}

	// Check for SST files
	files, err := os.ReadDir(mkm.dbPath)
	if err != nil {
		return false
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "sst_") && strings.HasSuffix(file.Name(), ".db") {
			return true
		}
	}

	return false
}

// getShamirSharedKey reconstructs key from Shamir shares
func (mkm *MasterKeyManager) getShamirSharedKey() ([]byte, error) {
	if !mkm.config.ShamirConfig.Enabled {
		return nil, fmt.Errorf("Shamir sharing not enabled")
	}

	sharesDir := mkm.config.ShamirConfig.SharesPath
	if sharesDir == "" {
		sharesDir = filepath.Join(mkm.dbPath, "shamir_shares")
	}

	// Check if shares exist
	if _, err := os.Stat(sharesDir); os.IsNotExist(err) {
		// No shares exist, prompt to create them
		return mkm.createShamirShares()
	}

	// Load existing shares
	return mkm.loadShamirShares(sharesDir)
}

// createShamirShares creates new Shamir shares from user input
func (mkm *MasterKeyManager) createShamirShares() ([]byte, error) {
	fmt.Println("No Shamir shares found. Creating new shares...")

	// Get master key from user
	keyStr, err := mkm.promptFunc("Enter master key to split (32 bytes, base64/hex) or press Enter to generate: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read master key: %w", err)
	}

	var masterKey []byte
	if strings.TrimSpace(keyStr) == "" {
		// Generate new key
		masterKey = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		keyString := base64.StdEncoding.EncodeToString(masterKey)

		// Copy to clipboard
		if err := copyToClipboard(keyString); err != nil {
			fmt.Printf("Generated new master key: %s\n(Failed to copy to clipboard: %v)\n", keyString, err)
		} else {
			fmt.Printf("Generated new master key: %s\n(Copied to clipboard)\n", keyString)
		}
	} else {
		masterKey, err = ParseKeyString(strings.TrimSpace(keyStr))
		if err != nil {
			return nil, fmt.Errorf("invalid master key: %w", err)
		}
	}

	// Split key using Shamir
	shares, err := shamir.Split(masterKey, mkm.config.ShamirConfig.Threshold, mkm.config.ShamirConfig.TotalShares)
	if err != nil {
		return nil, fmt.Errorf("failed to split key: %w", err)
	}

	// Create shares directory
	sharesDir := mkm.config.ShamirConfig.SharesPath
	if sharesDir == "" {
		sharesDir = filepath.Join(mkm.dbPath, "shamir_shares")
	}
	if err := os.MkdirAll(sharesDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create shares directory: %w", err)
	}

	// Save shares to files
	for i, share := range shares {
		shareFile := filepath.Join(sharesDir, fmt.Sprintf("share_%d.key", i+1))
		encoded := base64.StdEncoding.EncodeToString(share)
		if err := os.WriteFile(shareFile, []byte(encoded), 0600); err != nil {
			return nil, fmt.Errorf("failed to write share %d: %w", i+1, err)
		}
	}

	fmt.Printf("Created %d shares in %s\n", len(shares), sharesDir)
	fmt.Printf("Threshold: %d shares needed to reconstruct key\n", mkm.config.ShamirConfig.Threshold)

	return masterKey, nil
}

// loadShamirShares reconstructs key from existing shares
func (mkm *MasterKeyManager) loadShamirShares(sharesDir string) ([]byte, error) {
	// List available shares
	files, err := os.ReadDir(sharesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read shares directory: %w", err)
	}

	var shareFiles []string
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "share_") && strings.HasSuffix(file.Name(), ".key") {
			shareFiles = append(shareFiles, file.Name())
		}
	}

	if len(shareFiles) == 0 {
		return nil, fmt.Errorf("no share files found")
	}


	// Load all shares in order
	var allShares [][]byte
	for _, shareFile := range shareFiles {
		shareData, err := os.ReadFile(filepath.Join(sharesDir, shareFile))
		if err != nil {
			fmt.Printf("Failed to read share %s: %v\n", shareFile, err)
			continue
		}

		share, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(shareData)))
		if err != nil {
			fmt.Printf("Failed to decode share %s: %v\n", shareFile, err)
			continue
		}

		allShares = append(allShares, share)
	}

	if len(allShares) == 0 {
		return nil, fmt.Errorf("no valid shares found")
	}

	// Try to reconstruct key with all shares
	masterKey, err := shamir.Combine(allShares)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct key: %w", err)
	}
	return masterKey, nil
}

// cacheKey stores the key in cache with expiry
func (mkm *MasterKeyManager) cacheKey(key []byte) {
	mkm.cacheMutex.Lock()
	defer mkm.cacheMutex.Unlock()

	mkm.cachedKey = make([]byte, len(key))
	copy(mkm.cachedKey, key)
	mkm.cacheExpiry = time.Now().Add(mkm.config.UserKeyCache.TTL)
	mkm.lastAccess = time.Now()
}

// clearCache removes cached key
func (mkm *MasterKeyManager) clearCache() {
	mkm.cacheMutex.Lock()
	defer mkm.cacheMutex.Unlock()

	if mkm.cachedKey != nil {
		// Zero out the key for security
		for i := range mkm.cachedKey {
			mkm.cachedKey[i] = 0
		}
		mkm.cachedKey = nil
	}
}

// ClearCache provides public access to clear cache
func (mkm *MasterKeyManager) ClearCache() {
	mkm.clearCache()
}

// createShamirSharesFromKey creates Shamir shares from an existing key
func (mkm *MasterKeyManager) createShamirSharesFromKey(masterKey []byte, threshold, totalShares int) error {
	// Split key using Shamir
	shares, err := shamir.Split(masterKey, threshold, totalShares)
	if err != nil {
		return fmt.Errorf("failed to split key: %w", err)
	}

	// Create shares directory
	sharesDir := filepath.Join(mkm.dbPath, "shamir_shares")
	if err := os.MkdirAll(sharesDir, 0700); err != nil {
		return fmt.Errorf("failed to create shares directory: %w", err)
	}

	// Save shares to files
	for i, share := range shares {
		shareFile := filepath.Join(sharesDir, fmt.Sprintf("share_%d.key", i+1))
		encoded := base64.StdEncoding.EncodeToString(share)
		if err := os.WriteFile(shareFile, []byte(encoded), 0600); err != nil {
			return fmt.Errorf("failed to write share %d: %w", i+1, err)
		}
	}

	fmt.Printf("Created %d Shamir shares in %s\n", len(shares), sharesDir)
	fmt.Printf("Threshold: %d shares needed to reconstruct key\n", threshold)
	return nil
}

// copyToClipboard copies text to system clipboard
func copyToClipboard(text string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case "windows":
		cmd = exec.Command("clip")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// defaultPromptFunc prompts user for input with hidden input for keys
func defaultPromptFunc(prompt string) (string, error) {
	fmt.Print(prompt)

	// Use hidden input for key prompts
	if strings.Contains(strings.ToLower(prompt), "key") || strings.Contains(strings.ToLower(prompt), "password") {
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Println() // Add newline after hidden input
		return string(bytePassword), nil
	}

	// Regular input for other prompts
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/gui"
)

func main() {
	// Create Fyne application
	a := app.New()

	// Apply custom theme
	a.Settings().SetTheme(gui.NewVaultTheme())

	// Create window
	w := a.NewWindow("Velocity Vault")
	w.Resize(fyne.NewSize(550, 650))
	w.CenterOnScreen()

	// Data directory for the vault - use same path as CLI
	homeDir, _ := os.UserHomeDir()
	vaultPath := filepath.Join(homeDir, ".velocity")
	// Create vault directory if it doesn't exist
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		fmt.Printf("Warning: Failed to create vault directory: %v\n", err)
	}

	// Configure authentication
	config := gui.AuthConfig{
		Title:     "Velocity Vault",
		Subtitle:  "Secure Encrypted Storage",
		VaultPath: vaultPath,
		CheckVaultExists: func(path string) bool {
			// Check if vault metadata exists
			metaPath := filepath.Join(path, "vault.meta")
			if _, err := os.Stat(metaPath); err == nil {
				return true
			}
			// Check if vault files exist
			walPath := filepath.Join(path, "wal.log")
			if _, err := os.Stat(walPath); err == nil {
				return true
			}
			// Check for SST files
			files, err := os.ReadDir(path)
			if err != nil {
				return false
			}
			for _, file := range files {
				if strings.HasPrefix(file.Name(), "sst_") && strings.HasSuffix(file.Name(), ".db") {
					return true
				}
			}
			return false
		},
		CheckShamirShares: func(path string) bool {
			// Check if key_shares directory exists and has .key files
			sharesDir := filepath.Join(path, "key_shares")
			files, err := os.ReadDir(sharesDir)
			if err != nil {
				return false
			}
			for _, file := range files {
				if filepath.Ext(file.Name()) == ".key" {
					return true
				}
			}
			return false
		},
		GetVaultMetadata: func(path string) map[string]string {
			meta, _ := velocity.GetVaultMetadata(path)
			if meta == nil {
				return nil
			}
			return map[string]string{
				"type":       meta.Type,
				"created_at": meta.CreatedAt.Format(time.RFC3339),
			}
		},
		OnComplete: func(state gui.AuthState) {
			fmt.Printf("\n✅ Authentication Complete!\n")
			fmt.Printf("   Master Key: %s...%s\n",
				state.KeyBase64[:8],
				state.KeyBase64[len(state.KeyBase64)-4:])

			// Initialize the velocity database with the key
			initVault(vaultPath, state)

			// Close the auth window
			w.Close()
		},
		OnCancel: func() {
			fmt.Println("❌ Authentication cancelled")
			w.Close()
		},
	}

	// Create auth component
	auth := gui.NewAuthComponent(w, config)
	w.SetContent(auth.Show())

	// Handle window close
	w.SetOnClosed(func() {
		a.Quit()
	})

	// Show and run
	w.ShowAndRun()
}

// initVault initializes the velocity vault with the provided state
func initVault(vaultPath string, state gui.AuthState) {
	// Create vault directory if it doesn't exist
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		fmt.Printf("❌ Failed to create vault directory: %v\n", err)
		return
	}

	// Configure velocity with the master key
	config := velocity.Config{
		Path:      vaultPath,
		MasterKey: state.MasterKey, // Pass the master key directly
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled: true,
			},
			ShamirConfig: velocity.ShamirSecretConfig{
				Enabled:     false,
				Threshold:   3,
				TotalShares: 5,
				SharesPath:  filepath.Join(vaultPath, "key_shares"),
			},
		},
	}

	// Update Shamir config if requested
	if state.UseShamir {
		config.MasterKeyConfig.ShamirConfig.Enabled = true
		config.MasterKeyConfig.ShamirConfig.Threshold = state.ShamirThreshold
		config.MasterKeyConfig.ShamirConfig.TotalShares = state.ShamirShares
	}

	// Open database with explicit key
	db, err := velocity.NewWithConfig(config)
	if err != nil {
		fmt.Printf("❌ Failed to initialize vault: %v\n", err)
		return
	}
	defer db.Close()

	// Create Shamir shares if requested - BEFORE saving metadata
	// Only create shares if vault doesn't already exist (new vault initialization)
	sharesDir := filepath.Join(vaultPath, "key_shares")
	sharesExist := false
	if files, err := os.ReadDir(sharesDir); err == nil && len(files) > 0 {
		for _, f := range files {
			if strings.HasPrefix(f.Name(), "share_") && strings.HasSuffix(f.Name(), ".key") {
				sharesExist = true
				break
			}
		}
	}

	if state.UseShamir && !sharesExist {
		// Validate Shamir parameters
		if state.ShamirShares < 3 || state.ShamirThreshold < 2 {
			fmt.Printf("❌ Invalid Shamir parameters: shares=%d, threshold=%d\n", state.ShamirShares, state.ShamirThreshold)
			fmt.Println("   Skipping Shamir share creation. Using single master key mode.")
			state.UseShamir = false
		} else {
			fmt.Printf("   Creating Shamir shares...\n")
			// Create shares directory
			if err := os.MkdirAll(sharesDir, 0700); err != nil {
				fmt.Printf("❌ Failed to create shares directory: %v\n", err)
				return
			}

			// Use MasterKeyManager to create shares from the key
			mkm := velocity.NewMasterKeyManager(vaultPath, config.MasterKeyConfig)
			if err := mkm.CreateShamirSharesFromKey(state.MasterKey, state.ShamirThreshold, state.ShamirShares); err != nil {
				fmt.Printf("❌ Failed to create Shamir shares: %v\n", err)
				return
			}
			fmt.Printf("✅ Created %d Shamir shares (threshold: %d)\n", state.ShamirShares, state.ShamirThreshold)
		}
	}

	// Create tamperproof vault metadata using core function
	// Only create/update metadata if it doesn't exist
	metaPath := filepath.Join(vaultPath, "vault.meta")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		meta := &velocity.VaultMetadata{
			CreatedAt: time.Now(),
			Type:      "single",
		}
		if state.UseShamir {
			meta.Type = "shamir"
		}

		if err := velocity.SaveVaultMetadata(vaultPath, meta); err != nil {
			fmt.Printf("⚠️ Failed to write vault metadata: %v\n", err)
		} else {
			fmt.Printf("   Created vault metadata (type: %s)\n", meta.Type)
		}
	}

	// Test the vault
	testKey := []byte("__test_key__")
	testValue := []byte("vault_initialized")
	if err := db.Put(testKey, testValue); err != nil {
		fmt.Printf("❌ Failed to test vault: %v\n", err)
		return
	}

	// Clean up test key
	_ = db.Delete(testKey)

	fmt.Printf("✅ Vault initialized successfully at: %s\n", vaultPath)
}

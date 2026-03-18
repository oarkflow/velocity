package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"context"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/dialog"

	"github.com/oarkflow/velocity"
	velocitygui "github.com/oarkflow/velocity/gui"
	gui "github.com/oarkflow/velocity/gui/cmd/secretr"
	"github.com/oarkflow/velocity/gui/cmd/secretr/screens"
	"github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
)

func main() {
	// Set GUI mode to prevent auto-initialization of CLI client
	cli.SetGUIMode(true)

	// Create Fyne application
	a := app.New()

	// Apply custom theme
	a.Settings().SetTheme(velocitygui.NewVaultTheme())

	// Create window
	w := a.NewWindow("Secretr Vault")
	w.Resize(fyne.NewSize(1100, 750))
	w.CenterOnScreen()

	// data directory for Secretr
	// Secretr uses ~/.secretr/data for the velocity store
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".secretr")

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		dialog.ShowError(fmt.Errorf("Failed to create vault directory: %v", err), w)
		return
	}

	// Configure authentication
	config := velocitygui.AuthConfig{
		Title:     "Secretr Vault",
		Subtitle:  "Secure Enterprise Secrets Management",
		VaultPath: dataDir,
		CheckVaultExists: func(path string) bool {
			// Check if vault metadata exists
			metaPath := filepath.Join(path, "vault.meta")
			if _, err := os.Stat(metaPath); err == nil {
				return true
			}
			// Check for SST files (velocity specific)
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
		OnComplete: func(state velocitygui.AuthState) {
			// Initialize Secretr Client with the master key
			client, err := cli.InitializeClient(state.MasterKey)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Failed to initialize Secretr client: %v", err), w)
				return
			}

			// Initialize vault metadata/shares if needed
			initVault(dataDir, state)

			// 1. Check if auth is initiated (any identities exist)
			ctx := context.Background()
			idents, err := client.Identity.ListIdentities(ctx, identity.ListOptions{})

			authScreen := screens.NewAuthScreen(w, client, func() {
				// Final step: Show the Dashboard
				gui.ShowDashboard(a, w, client)
			})

			if err != nil || len(idents) == 0 {
				// No identities found, show registration
				authScreen.ShowRegistration()
			} else {
				// Identities exist, check if we have a valid session already
				if sess := client.CurrentSession(); sess != nil && sess.IsActive() {
					gui.ShowDashboard(a, w, client)
				} else {
					// Need to login
					authScreen.ShowLogin()
				}
			}
		},
		OnCancel: func() {
			w.Close()
		},
	}

	// Create auth component
	auth := velocitygui.NewAuthComponent(w, config)
	w.SetContent(auth.Show())

	// Handle window close
	w.SetOnClosed(func() {
		// Ensure client is closed
		cli.ResetClient()
		a.Quit()
	})

	// Show and run
	w.ShowAndRun()
}

// initVault initializes the velocity vault metadata if needed
// This mirrors the logic in the original main.go but tailored for Secretr
func initVault(vaultPath string, state velocitygui.AuthState) {
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

		velocity.SaveVaultMetadata(vaultPath, meta)
	}

	// Create Shamir shares if requested and not present
	// This is important for new vault creation flow
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
		os.MkdirAll(sharesDir, 0700)

		// Use velocity to create shares
		config := velocity.Config{
			Path:      vaultPath,
			MasterKey: state.MasterKey,
			MasterKeyConfig: velocity.MasterKeyConfig{
				Source: velocity.UserDefined,
				ShamirConfig: velocity.ShamirSecretConfig{
					Enabled:     true,
					Threshold:   state.ShamirThreshold,
					TotalShares: state.ShamirShares,
					SharesPath:  sharesDir,
				},
			},
		}

		mkm := velocity.NewMasterKeyManager(vaultPath, config.MasterKeyConfig)
		mkm.CreateShamirSharesFromKey(state.MasterKey, state.ShamirThreshold, state.ShamirShares)
	}
}

package gui

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/oarkflow/shamir"
	"golang.org/x/crypto/chacha20poly1305"
)

// Screen represents a named screen in the auth flow
type Screen string

const (
	ScreenWelcome      Screen = "welcome"
	ScreenInit         Screen = "init"
	ScreenGenerateKey  Screen = "generate_key"
	ScreenEnterKey     Screen = "enter_key"
	ScreenShamirConfig Screen = "shamir_config"
	ScreenUnlock       Screen = "unlock"
)

// AuthState holds the current authentication flow state
type AuthState struct {
	MasterKey       []byte
	KeyBase64       string
	UseShamir       bool
	ShamirShares    int
	ShamirThreshold int
	VaultExists     bool
	ShamirDetected  bool
	VaultType       string
}

// ScreenBuilder creates screen content
type ScreenBuilder struct {
	auth    *AuthComponent
	window  fyne.Window
	current Screen
}

// showError displays a professional error dialog
func (sb *ScreenBuilder) showError(title, message string) {
	dialog.ShowError(fmt.Errorf("%s", message), sb.window)
}

// NewScreenBuilder creates a new screen builder
func NewScreenBuilder(auth *AuthComponent, window fyne.Window) *ScreenBuilder {
	return &ScreenBuilder{
		auth:   auth,
		window: window,
	}
}

// WelcomeScreen creates the initial welcome screen
func (sb *ScreenBuilder) WelcomeScreen() fyne.CanvasObject {
	sb.current = ScreenWelcome

	// If vault exists, redirect to unlock screen
	if sb.auth.state.VaultExists {
		return sb.UnlockScreen()
	}

	// Logo image from bundled resource
	logo := RoundedLogo(resourceLogoPng)

	title := Heading(sb.auth.config.Title)
	subtitle := SubHeading(sb.auth.config.Subtitle)

	startBtn := PrimaryButton("Get Started", theme.NavigateNextIcon(), func() {
		sb.auth.navigateTo(ScreenInit)
	})

	content := container.NewVBox(
		container.NewCenter(logo),
		widget.NewSeparator(),
		title,
		subtitle,
		layout.NewSpacer(),
		container.NewHBox(layout.NewSpacer(), startBtn, layout.NewSpacer()),
		layout.NewSpacer(),
	)

	return container.NewPadded(content)
}

// InitScreen creates the initialization choice screen
func (sb *ScreenBuilder) InitScreen() fyne.CanvasObject {
	sb.current = ScreenInit

	// If vault exists, redirect to unlock screen (prevent key regeneration)
	if sb.auth.state.VaultExists {
		return sb.UnlockScreen()
	}

	title := Heading("Initialize Your Vault")
	subtitle := SubHeading("Choose how to set up your master key")

	generateBtn := widget.NewButton("🔐  Generate Secure Key", func() {
		sb.auth.navigateTo(ScreenGenerateKey)
	})
	generateBtn.Importance = widget.HighImportance

	enterBtn := widget.NewButton("📝  Enter Existing Key", func() {
		sb.auth.navigateTo(ScreenEnterKey)
	})
	enterBtn.Importance = widget.MediumImportance

	generateDesc := widget.NewLabel("Recommended: Generate a cryptographically secure random key")
	generateDesc.Wrapping = fyne.TextWrapWord
	generateDesc.Alignment = fyne.TextAlignCenter

	enterDesc := widget.NewLabel("Use your own key or restore from backup")
	enterDesc.Wrapping = fyne.TextWrapWord
	enterDesc.Alignment = fyne.TextAlignCenter

	generateCard := Card("Generate New Key", container.NewVBox(
		generateDesc,
		generateBtn,
	))

	enterCard := Card("Use Existing Key", container.NewVBox(
		enterDesc,
		enterBtn,
	))

	content := container.NewVBox(
		title,
		subtitle,
		layout.NewSpacer(),
		generateCard,
		enterCard,
		layout.NewSpacer(),
	)

	return container.NewPadded(content)
}

// GenerateKeyScreen creates the key generation screen
func (sb *ScreenBuilder) GenerateKeyScreen() fyne.CanvasObject {
	sb.current = ScreenGenerateKey

	// Generate a new key
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		sb.showError("Key Generation Failed", "Unable to generate a secure key. Please try again.")
		return container.NewCenter(widget.NewLabel("Error generating key"))
	}

	keyBase64 := base64.StdEncoding.EncodeToString(key)
	sb.auth.state.MasterKey = key
	sb.auth.state.KeyBase64 = keyBase64

	title := Heading("Your Master Key")
	subtitle := SubHeading("Keep this key safe - you'll need it to unlock your vault")

	keyDisplay := NewKeyDisplay(keyBase64, func() {
		sb.window.Clipboard().SetContent(keyBase64)
		dialog.ShowInformation("Copied!", "Master key copied to clipboard", sb.window)
	})

	warningLabel := WarningLabel("⚠️ Store this key safely! Without it, you cannot access your vault.")

	continueBtn := PrimaryButton("Continue", theme.NavigateNextIcon(), func() {
		sb.auth.navigateTo(ScreenShamirConfig)
	})

	backBtn := SecondaryButton("Back", theme.NavigateBackIcon(), func() {
		sb.auth.navigateTo(ScreenInit)
	})

	buttons := container.NewHBox(layout.NewSpacer(), backBtn, continueBtn, layout.NewSpacer())

	content := container.NewVBox(
		title,
		subtitle,
		layout.NewSpacer(),
		keyDisplay,
		warningLabel,
		layout.NewSpacer(),
		buttons,
	)

	return container.NewPadded(content)
}

// EnterKeyScreen creates the manual key entry screen
func (sb *ScreenBuilder) EnterKeyScreen() fyne.CanvasObject {
	sb.current = ScreenEnterKey

	title := Heading("Enter Your Master Key")
	subtitle := SubHeading("Enter your existing master key to unlock or initialize")

	keyEntry := NewSecureEntry()
	keyEntry.PlaceHolder = "Enter key (Base64 or Hex format, 32 bytes)"

	formatHint := widget.NewLabel("Supported formats: Base64 or Hex encoded (32 bytes)")
	formatHint.Alignment = fyne.TextAlignCenter

	validateKey := func() error {
		keyStr := keyEntry.Text
		if keyStr == "" {
			return fmt.Errorf("please enter a master key")
		}

		// Try base64 first
		key, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			// Try hex
			key, err = parseHexKey(keyStr)
			if err != nil {
				return fmt.Errorf("invalid key format: must be Base64 or Hex encoded")
			}
		}

		if len(key) != chacha20poly1305.KeySize {
			return fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
		}

		sb.auth.state.MasterKey = key
		sb.auth.state.KeyBase64 = base64.StdEncoding.EncodeToString(key)
		return nil
	}

	continueBtn := PrimaryButton("Continue", theme.NavigateNextIcon(), func() {
		if err := validateKey(); err != nil {
			sb.showError("Invalid Key", err.Error())
			return
		}
		sb.auth.navigateTo(ScreenShamirConfig)
	})

	backBtn := SecondaryButton("Back", theme.NavigateBackIcon(), func() {
		sb.auth.navigateTo(ScreenInit)
	})

	buttons := container.NewHBox(layout.NewSpacer(), backBtn, continueBtn, layout.NewSpacer())

	// entryWithToggle := keyEntry.WithToggle() // Toggle removed per requirements

	content := container.NewVBox(
		title,
		subtitle,
		layout.NewSpacer(),
		keyEntry,
		formatHint,
		layout.NewSpacer(),
		buttons,
	)

	return container.NewPadded(content)
}

// ShamirConfigScreen creates the Shamir sharing configuration screen
func (sb *ScreenBuilder) ShamirConfigScreen() fyne.CanvasObject {
	sb.current = ScreenShamirConfig

	title := Heading("Key Security Options")
	subtitle := SubHeading("Optionally split your key into shares for recovery")

	// Initialize default values first
	sb.auth.state.ShamirShares = 3
	sb.auth.state.ShamirThreshold = 2

	// Don't set UseShamir in checkbox callback - let the button handlers do it
	useShamirCheck := widget.NewCheck("Split key into shares for recovery", nil)

	sharesLabel := widget.NewLabel("Number of shares (minimum 3):")
	sharesEntry := widget.NewEntry()
	sharesEntry.SetText("3")
	sharesEntry.Validator = func(s string) error {
		if n, err := strconv.Atoi(s); err != nil || n < 3 {
			return fmt.Errorf("minimum 3 shares required")
		}
		return nil
	}

	thresholdInfo := widget.NewLabel("Threshold: 2 of 3 shares needed to recover")
	thresholdInfo.Wrapping = fyne.TextWrapWord

	updateThreshold := func() {
		n, err := strconv.Atoi(sharesEntry.Text)
		if err != nil || n < 3 {
			n = 3
		}
		threshold := (n + 1) / 2
		if threshold < 2 {
			threshold = 2
		}
		sb.auth.state.ShamirShares = n
		sb.auth.state.ShamirThreshold = threshold
		thresholdInfo.SetText(fmt.Sprintf("Threshold: %d of %d shares needed to recover", threshold, n))
	}
	sharesEntry.OnChanged = func(_ string) {
		updateThreshold()
	}
	updateThreshold()

	shamirConfig := container.NewVBox(
		sharesLabel,
		sharesEntry,
		thresholdInfo,
	)

	description := widget.NewLabel("Shamir Secret Sharing splits your master key into multiple shares. You can distribute these shares and require a threshold to reconstruct the key.")
	description.Wrapping = fyne.TextWrapWord

	cardContent := container.NewVBox(
		description,
		widget.NewSeparator(),
		useShamirCheck,
		shamirConfig,
	)

	skipBtn := SecondaryButton("Skip", theme.CancelIcon(), func() {
		sb.auth.state.UseShamir = false
		sb.auth.state.ShamirShares = 0
		sb.auth.state.ShamirThreshold = 0
		sb.auth.complete()
	})

	createBtn := PrimaryButton("Create Shares", theme.ConfirmIcon(), func() {
		// If user clicks "Create Shares", they want shares - always create them
		sb.auth.state.UseShamir = true

		// Get the final values from the entry field
		n, err := strconv.Atoi(sharesEntry.Text)
		if err != nil || n < 3 {
			n = 3
		}
		threshold := (n + 1) / 2
		if threshold < 2 {
			threshold = 2
		}

		sb.auth.state.ShamirShares = n
		sb.auth.state.ShamirThreshold = threshold
		sb.auth.complete()
	})

	buttons := container.NewHBox(layout.NewSpacer(), skipBtn, createBtn, layout.NewSpacer())

	content := container.NewVBox(
		title,
		subtitle,
		layout.NewSpacer(),
		Card("Shamir Secret Sharing", cardContent),
		layout.NewSpacer(),
		buttons,
	)

	return container.NewPadded(content)
}

// UnlockScreen creates the vault unlock screen
func (sb *ScreenBuilder) UnlockScreen() fyne.CanvasObject {
	sb.current = ScreenUnlock

	// Logo image from bundled resource
	logo := RoundedLogo(resourceLogoPng)

	title := Heading("Unlock Vault")
	subtitle := SubHeading("Enter your master key to access your vault")

	// Display vault type if known - IMPROVED
	vaultType := sb.auth.state.VaultType
	shamirDetected := sb.auth.state.ShamirDetected

	// Determine vault type display
	if vaultType == "" && shamirDetected {
		vaultType = "shamir"
	}

	keyEntry := NewSecureEntry()
	keyEntry.PlaceHolder = "Enter your master key..."

	validateAndUnlock := func() {
		keyStr := keyEntry.Text
		if keyStr == "" {
			sb.showError("Key Required", "Please enter your master key to unlock the vault.")
			return
		}

		// Try base64 first
		key, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			// Try hex
			key, err = parseHexKey(keyStr)
			if err != nil {
				sb.showError("Invalid Key Format", "The key must be in Base64 or Hex format. Please check and try again.")
				return
			}
		}

		if len(key) != chacha20poly1305.KeySize {
			sb.showError("Invalid Key Length", "The master key must be exactly 32 bytes. Please verify your key.")
			return
		}

		sb.auth.state.MasterKey = key
		sb.auth.state.KeyBase64 = base64.StdEncoding.EncodeToString(key)
		sb.auth.state.VaultExists = true
		sb.auth.complete()
	}

	keyEntry.OnSubmitted = func(_ string) {
		validateAndUnlock()
	}

	unlockBtn := PrimaryButton("Unlock", theme.LoginIcon(), validateAndUnlock)

	recoverLink := widget.NewHyperlink("Forgot key? Recover from shares", nil)
	recoverLink.OnTapped = func() {
		dialog.ShowInformation("Recovery", "Share recovery coming soon", sb.window)
	}

	// entryWithToggle := keyEntry.WithToggle() // Toggle removed per requirements

	// Shamir Detection and Auto-Recovery
	var shamirSection fyne.CanvasObject
	if sb.auth.state.ShamirDetected {
		recoverBtn := widget.NewButton("🔐 Recover from Local Shares", func() {
			sharesDir := filepath.Join(sb.auth.config.VaultPath, "key_shares")

			key, shareCount, err := recoverFromSharesWithInfo(sharesDir)
			if err != nil {
				fmt.Printf("Recovery failed: %v\n", err)
				sb.showError("Recovery Failed", fmt.Sprintf("Unable to recover key from shares: %v", err))
				return
			}

			sb.auth.state.MasterKey = key
			sb.auth.state.KeyBase64 = base64.StdEncoding.EncodeToString(key)
			sb.auth.state.VaultExists = true
			sb.auth.state.UseShamir = true

			// Set the share info based on what we found
			// We don't know the original total, but we know we used 'shareCount' shares
			// Set threshold to shareCount (what was needed) and total to shareCount
			sb.auth.state.ShamirShares = shareCount
			sb.auth.state.ShamirThreshold = shareCount

			sb.auth.complete()
		})
		recoverBtn.Importance = widget.HighImportance

		shamirSection = container.NewVBox(
			widget.NewSeparator(),
			Heading("Or"),
			recoverBtn,
		)
	} else {
		shamirSection = layout.NewSpacer()
	}

	content := container.NewVBox(
		container.NewCenter(logo),
		title,
		subtitle,
		layout.NewSpacer(),
		keyEntry,
		layout.NewSpacer(),
		container.NewHBox(layout.NewSpacer(), unlockBtn, layout.NewSpacer()),
		shamirSection,
		container.NewHBox(layout.NewSpacer(), recoverLink, layout.NewSpacer()),
	)

	return container.NewPadded(content)
}

// recoverFromSharesWithInfo reconstructs key from local shares and returns share count
func recoverFromSharesWithInfo(sharesDir string) ([]byte, int, error) {
	files, err := os.ReadDir(sharesDir)
	if err != nil {
		return nil, 0, fmt.Errorf("read dir: %w", err)
	}

	var allShares [][]byte
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "share_") && strings.HasSuffix(file.Name(), ".key") {
			filePath := filepath.Join(sharesDir, file.Name())
			content, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			share, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content)))
			if err != nil {
				continue
			}
			allShares = append(allShares, share)
		}
	}

	shareCount := len(allShares)
	if shareCount == 0 {
		return nil, 0, fmt.Errorf("no valid shares found in %s", sharesDir)
	}

	key, err := shamir.Combine(allShares)
	if err != nil {
		return nil, shareCount, fmt.Errorf("combine failed: %w", err)
	}
	return key, shareCount, nil
}

// BuildScreen builds the specified screen
func (sb *ScreenBuilder) BuildScreen(screen Screen) fyne.CanvasObject {
	switch screen {
	case ScreenWelcome:
		return sb.WelcomeScreen()
	case ScreenInit:
		return sb.InitScreen()
	case ScreenGenerateKey:
		return sb.GenerateKeyScreen()
	case ScreenEnterKey:
		return sb.EnterKeyScreen()
	case ScreenShamirConfig:
		return sb.ShamirConfigScreen()
	case ScreenUnlock:
		return sb.UnlockScreen()
	default:
		return sb.WelcomeScreen()
	}
}

// parseHexKey parses a hex-encoded key
func parseHexKey(s string) ([]byte, error) {
	// Remove common prefixes
	s = removePrefix(s, "0x")
	s = removePrefix(s, "0X")

	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length")
	}

	key := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		key[i/2] = b
	}
	return key, nil
}

func removePrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

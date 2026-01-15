package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// AuthConfig configures the authentication component
type AuthConfig struct {
	// Title displayed on welcome screen
	Title string
	// Subtitle displayed on welcome screen
	Subtitle string
	// VaultPath is the path to check for existing vault
	VaultPath string
	// OnComplete is called when authentication is complete
	OnComplete func(state AuthState)
	// OnCancel is called when user cancels authentication
	OnCancel func()
	// CheckVaultExists function to determine if vault already exists
	CheckVaultExists func(path string) bool
	// CheckShamirShares function to determine if Shamir shares exist
	CheckShamirShares func(path string) bool
	// GetVaultMetadata function to retrieve vault metadata
	GetVaultMetadata func(path string) map[string]string
}

// DefaultAuthConfig returns default configuration
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Title:    "Velocity Vault",
		Subtitle: "Secure Encrypted Storage",
	}
}

// AuthComponent is a reusable authentication flow component
type AuthComponent struct {
	config        AuthConfig
	window        fyne.Window
	container     *fyne.Container
	screenBuilder *ScreenBuilder
	state         AuthState
	currentScreen Screen
}

// NewAuthComponent creates a new authentication component
func NewAuthComponent(window fyne.Window, config AuthConfig) *AuthComponent {
	ac := &AuthComponent{
		config: config,
		window: window,
		state:  AuthState{},
	}
	ac.screenBuilder = NewScreenBuilder(ac, window)
	ac.container = container.NewStack()
	return ac
}

// Show displays the authentication flow
func (ac *AuthComponent) Show() fyne.CanvasObject {
	// Determine starting screen
	startScreen := ScreenWelcome
	if ac.config.CheckVaultExists != nil && ac.config.CheckVaultExists(ac.config.VaultPath) {
		startScreen = ScreenUnlock
		ac.state.VaultExists = true

		// Get vault metadata first to determine type
		if ac.config.GetVaultMetadata != nil {
			meta := ac.config.GetVaultMetadata(ac.config.VaultPath)
			if t, ok := meta["type"]; ok {
				ac.state.VaultType = t
				// If type is shamir, mark as detected
				if t == "shamir" {
					ac.state.ShamirDetected = true
				}
			}
		}

		// Check for Shamir shares if not already detected from metadata
		if !ac.state.ShamirDetected && ac.config.CheckShamirShares != nil && ac.config.CheckShamirShares(ac.config.VaultPath) {
			ac.state.ShamirDetected = true
			// If we detect shares but don't have metadata, assume shamir type
			if ac.state.VaultType == "" {
				ac.state.VaultType = "shamir"
			}
		}
	}

	ac.navigateTo(startScreen)
	return ac.container
}

// navigateTo navigates to the specified screen
func (ac *AuthComponent) navigateTo(screen Screen) {
	ac.currentScreen = screen
	content := ac.screenBuilder.BuildScreen(screen)

	// Clear and set new content
	ac.container.Objects = []fyne.CanvasObject{content}
	ac.container.Refresh()
}

// complete completes the authentication flow
func (ac *AuthComponent) complete() {
	if ac.config.OnComplete != nil {
		ac.config.OnComplete(ac.state)
	}
}

// cancel cancels the authentication flow
func (ac *AuthComponent) cancel() {
	if ac.config.OnCancel != nil {
		ac.config.OnCancel()
	}
}

// GetState returns the current authentication state
func (ac *AuthComponent) GetState() AuthState {
	return ac.state
}

// Reset resets the authentication state
func (ac *AuthComponent) Reset() {
	ac.state = AuthState{}
	ac.navigateTo(ScreenWelcome)
}

// SetVaultExists sets whether a vault already exists
func (ac *AuthComponent) SetVaultExists(exists bool) {
	ac.state.VaultExists = exists
}

// RunAuthFlow creates and runs a standalone authentication window
func RunAuthFlow(app fyne.App, config AuthConfig) *AuthComponent {
	window := app.NewWindow(config.Title)
	window.Resize(fyne.NewSize(500, 600))
	window.CenterOnScreen()

	// Apply custom theme
	app.Settings().SetTheme(NewVaultTheme())

	auth := NewAuthComponent(window, config)
	window.SetContent(auth.Show())

	return auth
}

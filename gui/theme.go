package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// VaultTheme implements a premium dark theme for the vault GUI
type VaultTheme struct {
	fyne.Theme
}

// NewVaultTheme creates a new vault theme
func NewVaultTheme() fyne.Theme {
	return &VaultTheme{Theme: theme.DefaultTheme()}
}

// Color returns the color for the specified name
func (t *VaultTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 15, G: 15, B: 25, A: 255} // Deep dark blue-black
	case theme.ColorNameButton:
		return color.NRGBA{R: 45, G: 45, B: 65, A: 255} // Subtle dark button
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 35, G: 35, B: 45, A: 255}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 88, G: 166, B: 255, A: 255} // Vibrant blue
	case theme.ColorNameFocus:
		return color.NRGBA{R: 88, G: 166, B: 255, A: 128}
	case theme.ColorNameHover:
		return color.NRGBA{R: 60, G: 60, B: 80, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 25, G: 25, B: 35, A: 255}
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 60, G: 60, B: 80, A: 255}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 120, G: 120, B: 140, A: 255}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 240, G: 240, B: 250, A: 255} // Light text
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 100, G: 100, B: 110, A: 255}
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 46, G: 204, B: 113, A: 255} // Green
	case theme.ColorNameError:
		return color.NRGBA{R: 231, G: 76, B: 60, A: 255} // Red
	case theme.ColorNameWarning:
		return color.NRGBA{R: 241, G: 196, B: 15, A: 255} // Yellow
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 80}
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 20, G: 20, B: 30, A: 240}
	case theme.ColorNameMenuBackground:
		return color.NRGBA{R: 30, G: 30, B: 45, A: 255}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 50, G: 50, B: 70, A: 255}
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 80, G: 80, B: 100, A: 255}
	}
	return t.Theme.Color(name, variant)
}

// Size returns the size for the specified name
func (t *VaultTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInnerPadding:
		return 12
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 24
	case theme.SizeNameSubHeadingText:
		return 18
	case theme.SizeNameInputBorder:
		return 2
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameScrollBar:
		return 12
	case theme.SizeNameScrollBarSmall:
		return 4
	}
	return t.Theme.Size(name)
}

// Accent colors for gradients and special elements
var (
	AccentBlue   = color.NRGBA{R: 88, G: 166, B: 255, A: 255}
	AccentPurple = color.NRGBA{R: 155, G: 89, B: 182, A: 255}
	AccentGreen  = color.NRGBA{R: 46, G: 204, B: 113, A: 255}
	AccentOrange = color.NRGBA{R: 230, G: 126, B: 34, A: 255}
	CardBg       = color.NRGBA{R: 25, G: 25, B: 40, A: 255}
	CardBorder   = color.NRGBA{R: 50, G: 50, B: 70, A: 255}
)

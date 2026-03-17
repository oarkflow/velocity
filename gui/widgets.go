package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// SecureEntry is a password entry with show/hide toggle
type SecureEntry struct {
	widget.Entry
	revealed bool
}

// NewSecureEntry creates a new secure password entry
func NewSecureEntry() *SecureEntry {
	e := &SecureEntry{}
	e.ExtendBaseWidget(e)
	e.Password = true
	e.PlaceHolder = "Enter your master key..."
	return e
}

// WithToggle returns the entry (toggle removed per requirements)
func (e *SecureEntry) WithToggle() fyne.CanvasObject {
	return e
}

// KeyDisplay is a widget for displaying a key with copy functionality
type KeyDisplay struct {
	widget.BaseWidget
	key      string
	revealed bool
	onCopy   func()
	keyLabel *widget.Label
}

// NewKeyDisplay creates a new key display widget
func NewKeyDisplay(key string, onCopy func()) *KeyDisplay {
	kd := &KeyDisplay{
		key:      key,
		revealed: false,
		onCopy:   onCopy,
	}
	kd.ExtendBaseWidget(kd)
	return kd
}

// CreateRenderer implements fyne.Widget
func (kd *KeyDisplay) CreateRenderer() fyne.WidgetRenderer {
	kd.keyLabel = widget.NewLabel(kd.getMaskedOrRevealed())
	kd.keyLabel.TextStyle = fyne.TextStyle{Monospace: true}
	kd.keyLabel.Alignment = fyne.TextAlignCenter
	kd.keyLabel.Wrapping = fyne.TextWrapBreak

	// Background card
	bg := canvas.NewRectangle(CardBg)
	bg.CornerRadius = 8
	bg.StrokeWidth = 1
	bg.StrokeColor = CardBorder

	// Mark as revealed so it shows the full key
	kd.revealed = true
	kd.keyLabel.SetText(kd.key)

	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if kd.onCopy != nil {
			kd.onCopy()
		}
	})
	copyBtn.Importance = widget.HighImportance

	buttons := container.NewHBox(layout.NewSpacer(), copyBtn, layout.NewSpacer())
	content := container.NewVBox(
		kd.keyLabel,
		buttons,
	)

	return widget.NewSimpleRenderer(container.NewStack(bg, container.NewPadded(content)))
}

func (kd *KeyDisplay) getMaskedOrRevealed() string {
	if kd.revealed {
		return kd.key
	}
	// Show first 8 and last 4 chars, mask the rest
	if len(kd.key) > 16 {
		return kd.key[:8] + "..." + kd.key[len(kd.key)-4:]
	}
	return "••••••••••••••••••••••••••••••••"
}

// SetKey updates the displayed key
func (kd *KeyDisplay) SetKey(key string) {
	kd.key = key
	if kd.keyLabel != nil {
		kd.keyLabel.SetText(kd.getMaskedOrRevealed())
	}
}

// Card creates a styled card container
func Card(title string, content fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(CardBg)
	bg.CornerRadius = 12
	bg.StrokeWidth = 1
	bg.StrokeColor = CardBorder

	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	cardContent := container.NewVBox(
		titleLabel,
		widget.NewSeparator(),
		content,
	)

	return container.NewStack(bg, container.NewPadded(cardContent))
}

// RoundedLogo creates a logo image with rounded background
func RoundedLogo(res fyne.Resource) fyne.CanvasObject {
	img := canvas.NewImageFromResource(res)
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(100, 100))

	bg := canvas.NewRectangle(color.Transparent)
	bg.CornerRadius = 20
	// We rely on the image being transparent or the container providing the rounding visual
	// Since Fyne doesn't support easy clipping, we place it in a rounded card-like container
	// for better visual integration

	return container.NewPadded(img)
}

// PrimaryButton creates a styled primary action button
func PrimaryButton(label string, icon fyne.Resource, onTap func()) *widget.Button {
	btn := widget.NewButtonWithIcon(label, icon, onTap)
	btn.Importance = widget.HighImportance
	return btn
}

// SecondaryButton creates a styled secondary button
func SecondaryButton(label string, icon fyne.Resource, onTap func()) *widget.Button {
	btn := widget.NewButtonWithIcon(label, icon, onTap)
	btn.Importance = widget.MediumImportance
	return btn
}

// WarningLabel creates a warning/info label
func WarningLabel(text string) fyne.CanvasObject {
	icon := widget.NewIcon(theme.WarningIcon())
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	// Use Border layout to give the label proper width (icon on left, label takes remaining space)
	return container.NewBorder(nil, nil, icon, nil, label)
}

// Heading creates a styled heading text using widget.Label
func Heading(text string) fyne.CanvasObject {
	// Use RichText for larger font size
	richText := widget.NewRichTextWithText(text)
	richText.Segments[0].(*widget.TextSegment).Style = widget.RichTextStyle{
		Alignment: fyne.TextAlignCenter,
		TextStyle: fyne.TextStyle{Bold: true},
		SizeName:  theme.SizeNameHeadingText,
	}
	return richText
}

// SubHeading creates a styled subheading text
func SubHeading(text string) fyne.CanvasObject {
	richText := widget.NewRichTextWithText(text)
	richText.Segments[0].(*widget.TextSegment).Style = widget.RichTextStyle{
		Alignment: fyne.TextAlignCenter,
		SizeName:  theme.SizeNameSubHeadingText,
		ColorName: theme.ColorNamePlaceHolder,
	}
	return richText
}

// Spacer creates a flexible spacer
func Spacer() fyne.CanvasObject {
	return layout.NewSpacer()
}

// CenteredContent creates content centered with max width
func CenteredContent(maxWidth float32, content fyne.CanvasObject) fyne.CanvasObject {
	return container.NewHBox(
		layout.NewSpacer(),
		container.New(&fixedWidthLayout{width: maxWidth}, content),
		layout.NewSpacer(),
	)
}

// fixedWidthLayout provides a layout with fixed width
type fixedWidthLayout struct {
	width float32
}

func (f *fixedWidthLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) == 0 {
		return fyne.NewSize(f.width, 0)
	}
	h := objects[0].MinSize().Height
	return fyne.NewSize(f.width, h)
}

func (f *fixedWidthLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		o.Resize(size)
		o.Move(fyne.NewPos(0, 0))
	}
}

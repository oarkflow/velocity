package screens

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/org"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type AuthScreen struct {
	window fyne.Window
	client *cli.Client
	onDone func()
}

func NewAuthScreen(w fyne.Window, client *cli.Client, onDone func()) *AuthScreen {
	return &AuthScreen{
		window: w,
		client: client,
		onDone: onDone,
	}
}

// ShowRegistration shows the setup screen for new vaults
func (a *AuthScreen) ShowRegistration() {
	title := widget.NewLabelWithStyle("System Initialization", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	desc := widget.NewLabelWithStyle("Create the initial administrator account.", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Admin Name")
	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("Admin Email")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")
	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm Password")

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Name", Widget: nameEntry},
			{Text: "Email", Widget: emailEntry},
			{Text: "Password", Widget: passwordEntry},
			{Text: "Confirm", Widget: confirmEntry},
		},
	}

	submitBtn := widget.NewButtonWithIcon("Initialize System", theme.ConfirmIcon(), func() {
		if nameEntry.Text == "" || emailEntry.Text == "" || passwordEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("all fields are required"), a.window)
			return
		}
		if passwordEntry.Text != confirmEntry.Text {
			dialog.ShowError(fmt.Errorf("passwords do not match"), a.window)
			return
		}

		ctx := context.Background()
		// 1. Create Identity
		ident, err := a.client.Identity.CreateHumanIdentity(ctx, identity.CreateHumanOptions{
			Name:     nameEntry.Text,
			Email:    emailEntry.Text,
			Password: passwordEntry.Text,
			Scopes:   []types.Scope{types.ScopeAdminAll},
		})
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to create admin: %v", err), a.window)
			return
		}

		// 2. Enroll Device
		_, err = a.client.Identity.EnrollDevice(ctx, identity.EnrollDeviceOptions{
			OwnerID: ident.ID,
			Name:    "Primary GUI Device",
			Type:    "gui",
		})
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to enroll device: %v", err), a.window)
			return
		}

		// 3. Create Default Org
		_, _ = a.client.Org.CreateOrganization(ctx, org.CreateOrgOptions{
			Name:    "Default",
			Slug:    "default",
			OwnerID: ident.ID,
		})

		dialog.ShowInformation("Success", "System initialized successfully. Please login.", a.window)
		a.ShowLogin()
	})
	submitBtn.Importance = widget.HighImportance

	content := container.NewVBox(
		title,
		desc,
		widget.NewSeparator(),
		form,
		container.NewCenter(submitBtn),
	)

	// Wrap in a container that forces a minimum width and height for the form
	formWrapper := container.NewGridWrap(fyne.NewSize(450, 450), container.NewPadded(content))
	a.window.SetContent(container.NewCenter(formWrapper))
}

// ShowLogin shows the login screen
func (a *AuthScreen) ShowLogin() {
	title := widget.NewLabelWithStyle("Login to Secretr", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("Email")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Email", Widget: emailEntry},
			{Text: "Password", Widget: passwordEntry},
		},
	}

	loginBtn := widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
		ctx := context.Background()
		session, err := a.client.Identity.Authenticate(ctx, emailEntry.Text, passwordEntry.Text, "")
		if err != nil {
			dialog.ShowError(fmt.Errorf("login failed: %v", err), a.window)
			return
		}

		if err := a.client.SaveSession(ctx, session); err != nil {
			dialog.ShowError(fmt.Errorf("failed to save session: %v", err), a.window)
			return
		}

		a.onDone()
	})
	loginBtn.Importance = widget.HighImportance

	// Bigger icon for login
	icon := widget.NewIcon(theme.AccountIcon())
	// We can't easily resize icons without a layout, but we can put it in a container that might scale it
	// if the icon supports it. In Fyne, icons usually scale to fit.

	content := container.NewVBox(
		container.NewCenter(container.NewGridWrap(fyne.NewSize(64, 64), icon)),
		title,
		widget.NewSeparator(),
		form,
		container.NewPadded(container.NewCenter(loginBtn)),
	)

	// Wrap in a container that forces a minimum width and height for the form
	formWrapper := container.NewGridWrap(fyne.NewSize(400, 350), container.NewPadded(content))
	a.window.SetContent(container.NewCenter(formWrapper))
}

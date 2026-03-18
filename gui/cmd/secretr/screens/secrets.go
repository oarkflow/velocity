package screens

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type SecretsScreen struct {
	window   fyne.Window
	client   *cli.Client
	list     *widget.List
	data     []*types.Secret
	filtered []*types.Secret
}

func NewSecretsScreen(w fyne.Window, client *cli.Client) *SecretsScreen {
	return &SecretsScreen{
		window: w,
		client: client,
	}
}

func (s *SecretsScreen) Layout() fyne.CanvasObject {
	// Toolbar
	toolbar := container.NewHBox(
		widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), s.refreshData),
		widget.NewButtonWithIcon("Add Secret", theme.ContentAddIcon(), s.showAddDialog),
	)

	// List
	s.list = widget.NewList(
		func() int { return len(s.filtered) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.AccountIcon()),
				widget.NewLabel("Secret Name"),
				widget.NewLabel("Type"),
			)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			if id >= len(s.filtered) {
				return
			}
			secret := s.filtered[id]
			box := o.(*fyne.Container)
			box.Objects[1].(*widget.Label).SetText(secret.Name)
			box.Objects[2].(*widget.Label).SetText(string(secret.Type))
		},
	)

	s.list.OnSelected = func(id widget.ListItemID) {
		if id < len(s.filtered) {
			s.showDetails(s.filtered[id])
			s.list.Unselect(id)
		}
	}

	// Initial load
	s.refreshData()

	return container.NewBorder(toolbar, nil, nil, nil, s.list)
}

func (s *SecretsScreen) refreshData() {
	ctx := context.Background()

	// List options
	opts := secrets.ListSecretsOptions{}

	// Check scope
	if err := s.client.RequireScope(types.ScopeSecretList); err != nil {
		dialog.ShowError(fmt.Errorf("Permission denied: %v", err), s.window)
		return
	}

	secrets, err := s.client.Secrets.List(ctx, opts)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to list secrets: %v", err), s.window)
		return
	}

	s.data = secrets
	s.filtered = secrets
	s.list.Refresh()
}

func (s *SecretsScreen) showAddDialog() {
	nameEntry := widget.NewEntry()
	nameEntry.PlaceHolder = "Secret Name"

	valueEntry := widget.NewMultiLineEntry()
	valueEntry.PlaceHolder = "Secret Value"

	envEntry := widget.NewEntry()
	envEntry.PlaceHolder = "Environment (optional)"

	// Form items
	items := []*widget.FormItem{
		widget.NewFormItem("Name", nameEntry),
		widget.NewFormItem("Value", valueEntry),
		widget.NewFormItem("Environment", envEntry),
	}

	// Show dialog
	dialog.ShowForm("Add Secret", "Create", "Cancel", items, func(confirm bool) {
		if confirm {
			s.createSecret(nameEntry.Text, valueEntry.Text, envEntry.Text)
		}
	}, s.window)
}

func (s *SecretsScreen) createSecret(name, value, env string) {
	if name == "" || value == "" {
		dialog.ShowError(fmt.Errorf("Name and Value are required"), s.window)
		return
	}

	ctx := context.Background()

	if err := s.client.RequireScope(types.ScopeSecretCreate); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	_, err := s.client.Secrets.Create(ctx, secrets.CreateSecretOptions{
		Name:        name,
		Value:       []byte(value),
		Type:        types.SecretTypeGeneric,
		Environment: env,
		CreatorID:   s.client.CurrentIdentityID(),
	})

	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to create secret: %v", err), s.window)
		return
	}

	s.refreshData()
}

func (s *SecretsScreen) showDetails(secret *types.Secret) {
	// Need to fetch full secret to show value
	ctx := context.Background()

	var valueStr string = "<hidden>"

	// Check permissions and fetch
	if err := s.client.RequireScope(types.ScopeSecretRead); err == nil {
		mfa := false
		if sess := s.client.CurrentSession(); sess != nil {
			mfa = sess.MFAVerified
		}

		val, err := s.client.Secrets.Get(ctx, secret.Name, s.client.CurrentIdentityID(), mfa)
		if err == nil {
			valueStr = string(val)
		} else {
			valueStr = fmt.Sprintf("Error fetching value: %v", err)
		}
	}

	// Copy button
	copyBtn := widget.NewButtonWithIcon("Copy Value", theme.ContentCopyIcon(), func() {
		s.window.Clipboard().SetContent(valueStr)
	})

	// Delete button
	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		dialog.ShowConfirm("Delete Secret", "Are you sure you want to delete "+secret.Name+"?", func(b bool) {
			if b {
				s.deleteSecret(secret.Name)
			}
		}, s.window)
	})
	deleteBtn.Importance = widget.DangerImportance

	valEntry := widget.NewEntry()
	valEntry.SetText(valueStr)

	content := container.NewVBox(
		widget.NewLabelWithStyle("Name: "+secret.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Type: "+string(secret.Type)),
		widget.NewLabel("Environment: "+secret.Environment),
		widget.NewLabel("Version: "+fmt.Sprintf("%d", secret.Version)),
		widget.NewLabel("Created: "+secret.CreatedAt.Time().Format(time.RFC3339)),
		widget.NewSeparator(),
		widget.NewLabel("Value:"),
		valEntry,
		container.NewHBox(copyBtn, deleteBtn),
	)

	// Use Custom Dialog or Window? Dialog is easier
	d := dialog.NewCustom("Secret Details", "Close", content, s.window)
	d.Resize(fyne.NewSize(400, 300))
	d.Show()
}

func (s *SecretsScreen) deleteSecret(name string) {
	ctx := context.Background()

	if err := s.client.RequireScope(types.ScopeSecretDelete); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	if err := s.client.Secrets.Delete(ctx, name, s.client.CurrentIdentityID()); err != nil {
		dialog.ShowError(fmt.Errorf("Failed to delete secret: %v", err), s.window)
		return
	}

	s.refreshData()
}

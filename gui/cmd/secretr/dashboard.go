package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/oarkflow/velocity/gui/cmd/secretr/screens"
	"github.com/oarkflow/velocity/internal/secretr/cli"
)

// ShowDashboard launches the main dashboard
func ShowDashboard(a fyne.App, w fyne.Window, client *cli.Client) {
	// Create screens
	secretsScreen := screens.NewSecretsScreen(w, client)
	filesScreen := screens.NewFilesScreen(w, client)

	// Content container (initially empty)
	content := container.NewMax()

	// Update content function
	var setContent func(fyne.CanvasObject)
	setContent = func(obj fyne.CanvasObject) {
		content.Objects = []fyne.CanvasObject{obj}
		content.Refresh()
	}

	// Start with secrets screen
	setContent(secretsScreen.Layout())

	// Sidebar
	sidebar := widget.NewList(
		func() int { return 3 },
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewIcon(theme.HomeIcon()), widget.NewLabel("Template"))
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			box := o.(*fyne.Container)
			icon := box.Objects[0].(*widget.Icon)
			label := box.Objects[1].(*widget.Label)

			switch id {
			case 0:
				label.SetText("Secrets")
				icon.SetResource(theme.AccountIcon())
			case 1:
				label.SetText("Files")
				icon.SetResource(theme.FileIcon())
			case 2:
				label.SetText("Lock Vault")
				icon.SetResource(theme.LoginIcon())
			}
		},
	)

	sidebar.OnSelected = func(id widget.ListItemID) {
		switch id {
		case 0:
			setContent(secretsScreen.Layout())
		case 1:
			setContent(filesScreen.Layout())
		case 2:
			// Lock vault = Close window (which triggers app quit per main.go)
			w.Close()
		}
	}

	// Select first item by default
	sidebar.Select(0)

	// Split container
	split := container.NewHSplit(sidebar, content)
	split.Offset = 0.2 // Sidebar takes 20%

	w.SetContent(split)
}

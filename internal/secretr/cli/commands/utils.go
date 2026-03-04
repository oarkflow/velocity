package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

var (
	GlobalYes bool
)

// Helper functions

func getFormat(cmd *cli.Command) string {
	if f := cmd.String("format"); f != "" {
		return f
	}
	return FormatTable
}

func output(cmd *cli.Command, data any) error {
	format := getFormat(cmd)
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	case FormatYAML:
		// Simple YAML-like output
		return outputYAML(data)
	case FormatTable:
		return outputTable(data)
	default:
		fmt.Println(data)
		return nil
	}
}

func outputYAML(data any) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func outputTable(data any) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	switch v := data.(type) {
	case []*types.Secret:
		fmt.Fprintln(w, "NAME\tTYPE\tVERSION\tENV\tSTATUS")
		for _, s := range v {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", s.Name, s.Type, s.Version, s.Environment, s.Status)
		}
	case []*types.Identity:
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tEMAIL\tSTATUS")
		for _, i := range v {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", i.ID, i.Name, i.Type, i.Email, i.Status)
		}
	case []*types.Device:
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tTRUST\tSTATUS")
		for _, d := range v {
			fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%s\n", d.ID, d.Name, d.Type, d.TrustScore, d.Status)
		}
	case []*types.Key:
		fmt.Fprintln(w, "ID\tTYPE\tVERSION\tPURPOSE\tSTATUS")
		for _, k := range v {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", k.ID, k.Type, k.Version, k.Purpose, k.Status)
		}
	case []*types.EncryptedFile:
		fmt.Fprintln(w, "NAME\tSIZE\tTYPE\tSEALED\tSTATUS")
		for _, f := range v {
			fmt.Fprintf(w, "%s\t%d\t%s\t%v\t%s\n", f.Name, f.Size, f.ContentType, f.Sealed, f.Status)
		}
	case []*types.AuditEvent:
		fmt.Fprintln(w, "TIME\tACTOR\tACTION\tRESOURCE\tSUCCESS")
		for _, e := range v {
			resID := ""
			if e.ResourceID != nil {
				resID = string(*e.ResourceID)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\n", e.Timestamp.Time().Format("2006-01-02 15:04:05"), e.ActorID, e.Action, resID, e.Success)
		}
	case []*types.Incident:
		fmt.Fprintln(w, "ID\tTYPE\tSEVERITY\tSTATUS\tDECLARED")
		for _, i := range v {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", i.ID, i.Type, i.Severity, i.Status, i.DeclaredAt.Time().Format("2006-01-02 15:04:05"))
		}
	default:
		return outputYAML(data)
	}
	return nil
}

func promptPassword(prompt string) (string, error) {
	if os.Getenv("SECRETR_ALLOW_INSECURE_PASSWORD_ENV") == "true" {
		if password := os.Getenv("SECRETR_PASSWORD"); password != "" {
			return password, nil
		}
	}

	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func confirm(prompt string) bool {
	if GlobalYes || os.Getenv("SECRETR_YES") == "true" {
		return true
	}
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

func success(format string, args ...any) {
	fmt.Printf("✓ "+format+"\n", args...)
}

func info(format string, args ...any) {
	fmt.Printf("ℹ "+format+"\n", args...)
}

func warning(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "⚠ "+format+"\n", args...)
}

// GetOrgID gets OrgID from flag or guess
func GetOrgID(ctx context.Context, cmd *cli.Command) (types.ID, error) {
	// 1) explicit flag
	id := cmd.String("org-id")
	if id != "" {
		return types.ID(id), nil
	}

	// 2) environment (setup_session exports ORG_ID)
	if env := os.Getenv("ORG_ID"); env != "" {
		return types.ID(env), nil
	}
	if env := os.Getenv("SECRETR_ORG_ID"); env != "" {
		return types.ID(env), nil
	}

	// 3) if client only has one org, use it
	c, err := client.GetClient()
	if err != nil {
		return "", err
	}

	orgs, err := c.Org.ListOrganizations(ctx)
	if err == nil && len(orgs) == 1 {
		return orgs[0].ID, nil
	}

	return "", fmt.Errorf("organization ID required via --org-id flag")
}

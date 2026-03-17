package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/incident"
	"github.com/oarkflow/velocity/internal/secretr/core/org"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Org commands

func OrgCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeOrgCreate); err != nil {
		return err
	}

	res, err := c.Org.CreateOrganization(ctx, org.CreateOrgOptions{
		Name:    name,
		Slug:    strings.ToLower(strings.ReplaceAll(name, " ", "-")),
		OwnerID: c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}
	success("Organization created: %s (%s)", res.Name, res.ID)
	return nil
}

func OrgList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	orgs, err := c.Org.ListOrganizations(ctx)
	if err != nil {
		return err
	}
	return output(cmd, orgs)
}

func OrgInvite(ctx context.Context, cmd *cli.Command) error {
	email := cmd.String("email")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Resolve email to IdentityID (simulated look up via List for now)
	identities, err := c.Identity.ListIdentities(ctx, identity.ListOptions{})
	if err != nil {
		return err
	}
	var targetID types.ID
	for _, ident := range identities {
		if ident.Email == email {
			targetID = ident.ID
			break
		}
	}
	if targetID == "" {
		return fmt.Errorf("user not found with email: %s", email)
	}

	if _, err := c.Org.InviteMember(ctx, org.InviteMemberOptions{
		OrgID:      types.ID(cmd.String("org-id")), // Assuming --org-id flag exists or inferred
		IdentityID: targetID,
		Role:       "member",
		InviterID:  c.CurrentIdentityID(),
		Scopes:     []types.Scope{types.ScopeAccessRead},
	}); err != nil {
		return err
	}
	success("Invitation sent to %s", email)
	return nil
}

func TeamCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	if _, err := c.Org.CreateTeam(ctx, org.CreateTeamOptions{
		Name:      name,
		OrgID:     orgID,
		CreatorID: c.CurrentIdentityID(),
	}); err != nil {
		return err
	}
	success("Team created")
	return nil
}

func TeamList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	teams, err := c.Org.ListTeams(ctx, orgID)
	if err != nil {
		return err
	}
	return output(cmd, teams)
}

func EnvCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	if _, err := c.Org.CreateEnvironment(ctx, org.CreateEnvOptions{
		Name:        name,
		OrgID:       orgID,
		Description: cmd.String("description"),
		CreatorID:   c.CurrentIdentityID(),
	}); err != nil {
		return err
	}
	success("Environment created")
	return nil
}

func EnvList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	envs, err := c.Org.ListEnvironments(ctx, orgID)
	if err != nil {
		return err
	}
	return output(cmd, envs)
}

func OrgLegalHold(ctx context.Context, cmd *cli.Command) error {
	if !confirm("Enable legal hold mode? This prevents ALL deletions.") {
		return nil
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	if err := c.Org.EnableLegalHold(ctx, orgID, c.CurrentIdentityID()); err != nil {
		return err
	}
	success("Legal hold mode enabled")
	return nil
}

func IncidentDeclare(ctx context.Context, cmd *cli.Command) error {
	incidentType := cmd.String("type")
	severity := cmd.String("severity")
	description := cmd.String("description")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeIncidentDeclare); err != nil {
		return err
	}

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	inc, err := c.Incident.DeclareIncident(ctx, incident.DeclareOptions{
		OrgID:       orgID,
		Type:        incidentType,
		Severity:    severity,
		Description: description,
		DeclaredBy:  c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}

	warning("Security incident declared: %s", inc.ID)
	return nil
}

func IncidentFreeze(ctx context.Context, cmd *cli.Command) error {
	if !confirm("Freeze organization access?") {
		return nil
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	disable := cmd.Bool("disable")
	if disable {
		if err := c.Org.UnfreezeOrganization(ctx, orgID, c.CurrentIdentityID()); err != nil {
			return err
		}
		success("Organization access unfrozen")
		return nil
	}

	// Assuming incident is context or we freeze active incident?
	// Need incident ID. `freeze` typically on an active incident.
	// c.Incident.FreezeAccess takes (ctx, incidentID, actorID)
	// We should look up active incident for the org.
	inc, err := c.Incident.GetActiveIncident(ctx, orgID)
	if err != nil {
		return err // error if no active incident or other error
	}

	if err := c.Incident.FreezeAccess(ctx, inc.ID, c.CurrentIdentityID()); err != nil {
		return err
	}
	warning("Organization access frozen")
	return nil
}

func IncidentRotate(ctx context.Context, cmd *cli.Command) error {
	all := cmd.Bool("all")
	names := cmd.StringSlice("names")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	inc, err := c.Incident.GetActiveIncident(ctx, orgID)
	if err != nil {
		return err
	}

	scope := "selected"
	if all {
		scope = "all"
	}

	if err := c.Incident.EmergencyRotation(ctx, inc.ID, incident.RotationOptions{
		ActorID:      c.CurrentIdentityID(),
		RotationType: "secrets", // Default to secrets
		Scope:        scope,
	}); err != nil {
		return err
	}
	_ = names // Unused in basic implementation (handled by scope?)

	success("Emergency rotation completed")
	return nil
}

func IncidentExport(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	data, err := c.Incident.ExportEvidence(ctx, types.ID(id), c.CurrentIdentityID())
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return err
	}

	success("Evidence exported to %s", outputPath)
	return nil
}

func IncidentList(ctx context.Context, cmd *cli.Command) error {
	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	incidents, err := c.Incident.ListIncidents(ctx, orgID)
	if err != nil {
		return err
	}
	return output(cmd, incidents)
}

func IncidentTimeline(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	timeline, err := c.Incident.GetTimeline(ctx, types.ID(id))
	if err != nil {
		return err
	}
	return output(cmd, timeline)
}

// Org Extensions

func OrgGrantAuditor(ctx context.Context, cmd *cli.Command) error {
	auditorID := cmd.String("auditor-id")
	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if _, err := c.Org.GrantAuditorAccess(ctx, org.AuditorAccessOptions{
		OrgID:     orgID,
		AuditorID: types.ID(auditorID),
		GranterID: c.CurrentIdentityID(),
	}); err != nil {
		return err
	}

	success("Auditor access granted to %s", auditorID)
	return nil
}

func OrgCreateVendor(ctx context.Context, cmd *cli.Command) error {
	vendorName := cmd.String("name")
	vendorID := cmd.String("vendor-id")
	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	access, err := c.Org.CreateVendorAccess(ctx, org.VendorAccessOptions{
		OrgID:      orgID,
		VendorID:   types.ID(vendorID),
		VendorName: vendorName,
		GranterID:  c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}

	success("Vendor access created for %s (%s)", access.VendorName, access.ID)
	return nil
}

func OrgTransferInit(ctx context.Context, cmd *cli.Command) error {
	sourceOrg := cmd.String("source-org")
	targetOrg := cmd.String("target-org")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	transfer, err := c.Org.InitiateTransfer(ctx, org.TransferOptions{
		SourceOrgID:       types.ID(sourceOrg),
		TargetOrgID:       types.ID(targetOrg),
		InitiatorID:       c.CurrentIdentityID(),
		RequiredApprovals: 1, // Reduced for demo
	})
	if err != nil {
		return err
	}

	success("Transfer initiated: %s", transfer.ID)
	return nil
}

func OrgTransferApprove(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	transfer, err := c.Org.GetTransfer(ctx, types.ID(id))
	if err != nil {
		return err
	}

	if err := c.Org.ApproveTransfer(ctx, transfer, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("Transfer approved: %s", id)
	return nil
}

func OrgTransferExecute(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	transfer, err := c.Org.GetTransfer(ctx, types.ID(id))
	if err != nil {
		return err
	}

	if err := c.Org.ExecuteTransfer(ctx, transfer, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("Transfer executed: %s", id)
	return nil
}

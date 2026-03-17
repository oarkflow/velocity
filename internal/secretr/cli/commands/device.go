package commands

import (
	"context"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Device commands

func DeviceEnroll(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	deviceType := cmd.String("type")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireSession(); err != nil {
		return err
	}

	device, err := c.Identity.EnrollDevice(ctx, identity.EnrollDeviceOptions{
		OwnerID: c.CurrentIdentityID(),
		Name:    name,
		Type:    deviceType,
	})
	if err != nil {
		return err
	}
	success("Device enrolled: %s (ID: %s)", device.Name, device.ID)
	return nil
}

func DeviceList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	devices, err := c.Identity.ListDevices(ctx, c.CurrentIdentityID())
	if err != nil {
		return err
	}
	return output(cmd, devices)
}

func DeviceRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.Identity.RevokeDevice(ctx, types.ID(id)); err != nil {
		return err
	}
	success("Device revoked: %s", id)
	return nil
}

func DeviceTrust(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	device, err := c.Identity.GetDevice(ctx, types.ID(id))
	if err != nil {
		return err
	}
	info("Trust score: %.2f", device.TrustScore)
	return nil
}

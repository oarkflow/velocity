package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/velocity"
	"github.com/urfave/cli/v3"
)

func secretCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "Secret management operations",
		Commands: []*cli.Command{
			{
				Name:      "set",
				Usage:     "Store a secret",
				ArgsUsage: "<name> <value>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return fmt.Errorf("usage: velocity secret set <name> <value>")
					}
					name := cmd.Args().Get(0)
					value := cmd.Args().Get(1)
					key := fmt.Sprintf("secret:general:%s", name)
					if err := db.Put([]byte(key), []byte(value)); err != nil {
						return fmt.Errorf("failed to set secret: %w", err)
					}
					fmt.Printf("Stored secret: %s\n", name)
					return nil
				},
			},
			{
				Name:      "get",
				Usage:     "Retrieve a secret",
				ArgsUsage: "<name>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return fmt.Errorf("usage: velocity secret get <name>")
					}
					name := cmd.Args().Get(0)
					key := fmt.Sprintf("secret:general:%s", name)
					val, err := db.Get([]byte(key))
					if err != nil {
						return fmt.Errorf("secret not found: %s", name)
					}
					fmt.Println(string(val))
					return nil
				},
			},
		},
	}
}

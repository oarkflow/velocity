package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/velocity"
	"github.com/urfave/cli/v3"
)

func dataCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "data",
		Usage: "Data storage operations",
		Commands: []*cli.Command{
			{
				Name:      "put",
				Usage:     "Store a key-value pair",
				ArgsUsage: "<key> <value>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 {
						return fmt.Errorf("usage: velocity data put <key> <value>")
					}
					key := cmd.Args().Get(0)
					value := cmd.Args().Get(1)
					if err := db.Put([]byte(key), []byte(value)); err != nil {
						return fmt.Errorf("failed to put: %w", err)
					}
					fmt.Printf("Stored: %s\n", key)
					return nil
				},
			},
			{
				Name:      "get",
				Usage:     "Retrieve a value",
				ArgsUsage: "<key>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return fmt.Errorf("usage: velocity data get <key>")
					}
					key := cmd.Args().Get(0)
					val, err := db.Get([]byte(key))
					if err != nil {
						return fmt.Errorf("failed to get: %w", err)
					}
					fmt.Println(string(val))
					return nil
				},
			},
		},
	}
}

package sqldriver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oarkflow/velocity"
)

var (
	engines   = make(map[string]*velocity.DB)
	enginesMu sync.Mutex
)

// DSNConfigs allows injecting pre-configured velocity.Config setups for a given DSN.
// This is extremely useful for setting up SearchSchemas before using sql.Open().
var DSNConfigs = make(map[string]velocity.Config)

// Define the name the driver will be registered with
const DriverName = "velocity"

func init() {
	sql.Register(DriverName, &Driver{})
}

// Driver implements the database/sql/driver.Driver interface for Velocity DB.
type Driver struct{}

// Open returns a new connection to the database.
// The name is the path to the velocity database director.
// E.g., sql.Open("velocity", "./data")
//
// URL parameters can be used to configure FIPS mode, etc (e.g., ./data?fips=true)
func (d *Driver) Open(name string) (driver.Conn, error) {
	config, path, err := parseDSN(name)
	if err != nil {
		return nil, fmt.Errorf("velocity driver: invalid dsn: %w", err)
	}

	config.Path = path

	enginesMu.Lock()
	defer enginesMu.Unlock()

	db, ok := engines[path]
	if !ok {
		db, err = velocity.NewWithConfig(*config)
		if err != nil {
			return nil, fmt.Errorf("velocity driver: failed to open db at %s: %w", path, err)
		}
		engines[path] = db
	}

	return &Conn{db: db}, nil
}

// OpenConnector must optionally be implemented by a Driver in order to
// intercept Open calls and return a non-driver.Conn interface.
func (d *Driver) OpenConnector(name string) (driver.Connector, error) {
	return &connector{d: d, name: name}, nil
}

// connector implements driver.Connector
type connector struct {
	d    *Driver
	name string
}

func (c *connector) Connect(context.Context) (driver.Conn, error) {
	return c.d.Open(c.name)
}

func (c *connector) Driver() driver.Driver {
	return c.d
}

// parseDSN parses the Data Source Name to extract the path and configuration options.
// Example DSNs:
// "velocity://./vault?fips=true"
// "./vault"
func parseDSN(dsn string) (*velocity.Config, string, error) {
	dsn = strings.TrimPrefix(dsn, "velocity://")
	parts := strings.Split(dsn, "?")
	path := parts[0]

	// Use an absolute path if it's relative
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "./") && !strings.HasPrefix(path, "../") {
		path = "./" + path
	}

	config := velocity.Config{}

	// Lookup if we mapped a specific config to this named DSN manually
	if mapped, ok := DSNConfigs[dsn]; ok {
		config = mapped
	}

	config.Path = path

	if len(parts) > 1 {
		// Future expansion for DSN parameters (e.g., query := parts[1])
	}
	return &config, path, nil
}

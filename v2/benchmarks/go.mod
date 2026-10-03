module github.com/oarkflow/velocity/v2/benchmarks

go 1.27.0

replace github.com/oarkflow/velocity/v2 => ../

require (
	github.com/mattn/go-sqlite3 v1.14.52
	github.com/oarkflow/velocity/v2 v2.0.0-00010101000000-000000000000
	github.com/redis/go-redis/v9 v9.22.0
	go.etcd.io/bbolt v1.5.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/oarkflow/bcl v0.0.36 // indirect
	github.com/oarkflow/config v0.0.1 // indirect
	github.com/oarkflow/convert v0.0.6 // indirect
	github.com/oarkflow/sqlparser v0.0.2 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

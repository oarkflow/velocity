package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/web"
)

func usage() {
	fmt.Print(`Usage:
  go run ./cmd serve [--http PORT] [--tcp PORT] [--dir PATH] [--users PATH]
  go run ./cmd put --dir PATH <key> <value>
  go run ./cmd get --dir PATH <key>
  go run ./cmd delete --dir PATH <key>

Examples:
  go run ./cmd serve --http 8081 --tcp 8080 --dir ./velocitydb_server
  go run ./cmd put --dir ./mydb mykey myvalue
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		httpPort := serveCmd.String("http", "8081", "HTTP server port")
		tcpPort := serveCmd.String("tcp", "8080", "TCP server port")
		dataDir := serveCmd.String("dir", "./velocitydb_server", "Database directory")
		usersDB := serveCmd.String("users", "./users.db", "Users DB path (sqlite)")
		serveCmd.Parse(os.Args[2:])
		runServe(*dataDir, *usersDB, *httpPort, *tcpPort)

	case "put":
		putCmd := flag.NewFlagSet("put", flag.ExitOnError)
		dataDir := putCmd.String("dir", "./velocitydb_data", "Database directory")
		putCmd.Parse(os.Args[2:])
		args := putCmd.Args()
		if len(args) != 2 {
			fmt.Println("put requires key and value")
			os.Exit(2)
		}
		runSimplePut(*dataDir, args[0], args[1])

	case "get":
		getCmd := flag.NewFlagSet("get", flag.ExitOnError)
		dataDir := getCmd.String("dir", "./velocitydb_data", "Database directory")
		getCmd.Parse(os.Args[2:])
		args := getCmd.Args()
		if len(args) != 1 {
			fmt.Println("get requires key")
			os.Exit(2)
		}
		runSimpleGet(*dataDir, args[0])

	case "delete":
		delCmd := flag.NewFlagSet("delete", flag.ExitOnError)
		dataDir := delCmd.String("dir", "./velocitydb_data", "Database directory")
		delCmd.Parse(os.Args[2:])
		args := delCmd.Args()
		if len(args) != 1 {
			fmt.Println("delete requires key")
			os.Exit(2)
		}
		runSimpleDelete(*dataDir, args[0])

	default:
		usage()
		os.Exit(1)
	}
}

func runServe(dataDir, usersDB, httpPort, tcpPort string) {
	log.Printf("Starting servers: DB=%s users=%s http=%s tcp=%s\n", dataDir, usersDB, httpPort, tcpPort)
	// Ensure data dir exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	db, err := velocity.New(dataDir)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// default cache mode: balanced for good default memory/perf tradeoff
	db.SetCacheMode("balanced")

	userDB, err := web.NewSQLiteUserStorage(usersDB)
	if err != nil {
		log.Fatalf("failed to initialize user storage: %v", err)
	}
	defer userDB.Close()

	// create default admin if not exists
	ctx := context.Background()
	if _, err := userDB.GetUserByUsername(ctx, "admin"); err != nil {
		adminUser := &web.User{Username: "admin", Email: "admin@example.com", Password: "password123", Role: "admin"}
		if err := userDB.CreateUser(ctx, adminUser); err != nil {
			log.Fatalf("failed to create admin user: %v", err)
		}
		log.Println("Created default admin user (username: admin, password: password123)")
	}

	tcpServer := web.NewTCPServer(db, tcpPort, userDB)
	if err := tcpServer.Start(); err != nil {
		log.Fatalf("failed to start tcp server: %v", err)
	}
	defer tcpServer.Stop()

	httpServer := web.NewHTTPServer(db, httpPort, userDB)
	go func() {
		if err := httpServer.Start(); err != nil {
			log.Fatalf("failed to start http server: %v", err)
		}
	}()
	defer httpServer.Stop()

	log.Printf("Servers started: tcp=%s http=%s (admin UI: http://localhost:%s/admin)", tcpPort, httpPort, httpPort)

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down servers...")
}

func runSimplePut(dataDir, key, value string) {
	abs, _ := filepath.Abs(dataDir)
	db, err := velocity.New(abs)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	if err := db.Put([]byte(key), []byte(value)); err != nil {
		log.Fatalf("put failed: %v", err)
	}
	fmt.Println("OK")
}

func runSimpleGet(dataDir, key string) {
	abs, _ := filepath.Abs(dataDir)
	db, err := velocity.New(abs)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	v, err := db.Get([]byte(key))
	if err != nil {
		log.Fatalf("get failed: %v", err)
	}
	fmt.Println(string(v))
}

func runSimpleDelete(dataDir, key string) {
	abs, _ := filepath.Abs(dataDir)
	db, err := velocity.New(abs)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	if err := db.Delete([]byte(key)); err != nil {
		log.Fatalf("delete failed: %v", err)
	}
	fmt.Println("OK")
}

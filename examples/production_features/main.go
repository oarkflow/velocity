package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/oarkflow/velocity"
	_ "github.com/oarkflow/velocity/sqldriver" // Register velocity driver
)

func main() {
	// 1. Initialize Velocity with Production Configuration
	path := "./velocity_demo_db"
	cfg := velocity.Config{
		Path:      path,
		NodeID:    "node-prod-01",
		JWTSecret: "super-secure-jwt-secret-for-demo",
	}

	db, err := velocity.NewWithConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to open velocity: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	fmt.Println("=== 🚀 Velocity Production Features Demo ===")

	// 2. SQL Transactions (via Standard database/sql)
	fmt.Println("\n[1] Demonstrating SQL Transactions...")
	// We use the "velocity" driver registered by sqldriver package
	sqlDB, err := sql.Open("velocity", path)
	if err != nil {
		log.Fatalf("Failed to open sql connection: %v", err)
	}
	defer sqlDB.Close()

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to begin transaction: %v", err)
	}

	// Insert multiple records atomically
	_, err = tx.ExecContext(ctx, "INSERT INTO demo_table (id, name) VALUES (1, 'Alice')")
	if err != nil {
		tx.Rollback()
		log.Fatalf("Insert 1 failed: %v", err)
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO demo_table (id, name) VALUES (2, 'Bob')")
	if err != nil {
		tx.Rollback()
		log.Fatalf("Insert 2 failed: %v", err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("Commit failed: %v", err)
	}
	fmt.Println("Successfully committed transaction with 2 records.")

	// 3. Chunked Streaming Encryption
	fmt.Println("\n[2] Demonstrating Chunked Streaming Encryption...")
	largeData := strings.Repeat("This is a demo of velocity chunked streaming encryption. ", 100)
	dataReader := strings.NewReader(largeData)

	objectPath := "documents/large_encrypted_file.txt"
	// Store with encryption (size is required for streaming)
	_, err = db.StoreObjectStream(objectPath, "text/plain", "demo_user", dataReader, int64(len(largeData)), &velocity.ObjectOptions{
		Encrypt: true,
	})
	if err != nil {
		log.Fatalf("Failed to store object stream: %v", err)
	}

	// Retrieve via streaming
	getReader, _, err := db.GetObjectStream(objectPath, "demo_user")
	if err != nil {
		log.Fatalf("Failed to get object stream: %v", err)
	}
	defer getReader.Close()

	retrieved, err := io.ReadAll(getReader)
	if err != nil {
		log.Fatalf("Failed to read partially: %v", err)
	}
	fmt.Printf("Retrieved encrypted stream. Length matches: %v\n", len(retrieved) == len(largeData))

	// 4. Compliance: GDPR Personal Data Collection
	fmt.Println("\n[3] Demonstrating GDPR Data Portability (Subject Access Request)...")
	gc := velocity.NewGDPRController(db)
	// Registring a dummy subject for the demo
	// (In real life, subjects are created during PII tagging)
	personalData, err := gc.RequestRightToAccess(ctx, "alice@example.com")
	if err != nil {
		// This might fail if no data is found, which is fine for a demo
		fmt.Printf("GDPR access request result: %v\n", err)
	} else {
		fmt.Printf("Collected SAR package for subject 'alice@example.com'. Size: %d bytes\n", len(personalData))
	}

	// 5. Compliance: Forensic Audit Trail Export
	fmt.Println("\n[4] Demonstrating Forensic Audit Trail Export...")
	alm := velocity.NewAuditLogManager(db)

	exportPath := "./forensic_audit_export.json"
	if err := alm.ExportForensics(exportPath); err != nil {
		log.Fatalf("Forensic export failed: %v", err)
	}
	fmt.Printf("Immutable audit trail exported to %s\n", exportPath)

	// 6. Compliance: Cryptographic Erasure (Right to be Forgotten)
	fmt.Println("\n[5] Demonstrating Cryptographic Erasure...")
	if err := gc.RequestRightToErasure(ctx, "bob@example.com"); err != nil {
		fmt.Printf("Erasure request result: %v\n", err)
	} else {
		fmt.Println("Erasure request for 'bob@example.com' completed.")
	}

	fmt.Println("\n=== ✅ Demo Completed Successfully ===")

	// Cleanup
	_ = os.RemoveAll(path)
	_ = os.Remove(exportPath)
}

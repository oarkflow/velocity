package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func main() {
	fmt.Println("=== Velocity Envelope Bundle System Demo ===")

	db, err := velocity.NewWithConfig(velocity.Config{
		Path: "./bundle_demo_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()

	envID := createBundleEnvelope(db, ctx)
	exportAndImportBundle(db, ctx, envID)
}

func createBundleEnvelope(db *velocity.DB, ctx context.Context) string {
	fmt.Println("\n📦 Creating Envelope with Resource Bundle")
	fmt.Println("=========================================")

	// Store a secret
	if err := db.Put([]byte("secret:case:api_key"), []byte(`{"key":"sk_test_12345","endpoint":"https://api.case.gov"}`)); err != nil {
		log.Fatal("Failed to store secret:", err)
	}
	fmt.Println("✓ Stored secret resource")

	// Store a file in object storage
	fileContent := []byte("This is sample CCTV footage evidence data for case 001")
	if _, err := db.StoreObject("evidence/cctv/case-001/camera5.mp4", "application/octet-stream", "system", fileContent, nil); err != nil {
		log.Fatal("Failed to store object:", err)
	}
	fmt.Println("✓ Stored file resource")

	docData := map[string]string{
		"title":       "Case Evidence Document",
		"description": "Original evidence document",
		"author":      "Detective John Doe",
	}
	docJSON, _ := json.Marshal(docData)

	resources := []velocity.EnvelopeResource{
		{
			ID:     "res-1",
			Type:   "file",
			Name:   "cctv_footage.mp4",
			Path:   "evidence/cctv/case-001/camera5.mp4",
			Metadata: map[string]string{"camera": "5", "timestamp": "2026-01-20T14:30:00Z"},
		},
		{
			ID:        "res-2",
			Type:      "secret",
			Name:      "api_credentials",
			SecretRef: "secret:case:api_key",
		},
		{
			ID:    "res-3",
			Type:  "kv",
			Name:  "case_metadata",
			Key:   "case.001",
			Value: docJSON,
		},
	}

	payload := velocity.EnvelopePayload{
		Kind:      "bundle",
		Resources: resources,
		Metadata: map[string]string{
			"bundle_version": "1.0",
		},
	}

	req := &velocity.EnvelopeRequest{
		Label:         "Case 001 Evidence Bundle",
		Type:          velocity.EnvelopeTypeInvestigationRecord,
		CreatedBy:     "detective-john-doe",
		CaseReference: "CR-2026-001",
		Payload:       payload,
	}

	env, err := db.CreateEnvelope(ctx, req)
	if err != nil {
		log.Fatal("Failed to create envelope:", err)
	}

	fmt.Printf("✓ Created bundle envelope: %s\n", env.EnvelopeID)
	fmt.Printf("  Label: %s\n", env.Label)
	fmt.Printf("  Type: %s\n", env.Type)
	fmt.Printf("  Resources: %d\n", len(env.Payload.Resources))

	for i, res := range env.Payload.Resources {
		fmt.Printf("  [%d] %s (%s)\n", i+1, res.Name, res.Type)
	}

	resolved, err := db.ResolveResources(env.Payload)
	if err != nil {
		fmt.Printf("  Note: Some resources could not be resolved: %v\n", err)
	} else {
		fmt.Printf("  Resolved: %d resources\n", len(resolved))
	}

	return env.EnvelopeID
}

func exportAndImportBundle(db *velocity.DB, ctx context.Context, envID string) {
	fmt.Println("\n🔄 Exporting and Importing Bundle")
	fmt.Println("====================================")

	exportPath := "./evidence_" + envID + ".sec"

	if err := db.ExportEnvelope(ctx, envID, exportPath); err != nil {
		fmt.Printf("Export not available in demo: %v\n", err)
		return
	}

	fmt.Printf("✓ Exported to: %s\n", exportPath)

	importedEnv, err := db.ImportEnvelope(ctx, exportPath)
	if err != nil {
		fmt.Printf("Import not available in demo: %v\n", err)
		return
	}

	fmt.Printf("✓ Imported envelope: %s\n", importedEnv.EnvelopeID)
	fmt.Printf("  Resources: %d\n", len(importedEnv.Payload.Resources))
}

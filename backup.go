package velocity

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupMetadata contains information about a backup
type BackupMetadata struct {
	Version         string            `json:"version"`
	CreatedAt       time.Time         `json:"created_at"`
	DBPath          string            `json:"db_path"`
	Compressed      bool              `json:"compressed"`
	Encrypted       bool              `json:"encrypted"`
	ItemCount       int               `json:"item_count"`
	TotalSize       int64             `json:"total_size"`
	User            string            `json:"user"`
	Description     string            `json:"description,omitempty"`
	Signature       BackupSignature   `json:"signature"`
	AuditID         string            `json:"audit_id"`
	IntegrityCheck  string            `json:"integrity_check"`
	ChainLinks      []string          `json:"chain_links,omitempty"`
}

// BackupItem represents an item in a backup
type BackupItem struct {
	Type     string          `json:"type"` // "secret", "file", "folder", "object"
	Path     string          `json:"path"`
	Data     json.RawMessage `json:"data,omitempty"`
	Metadata map[string]any  `json:"metadata,omitempty"`
}

// BackupOptions configures backup behavior
type BackupOptions struct {
	OutputPath   string
	Compress     bool
	Encrypt      bool
	IncludeTypes []string // "secrets", "files", "folders", "objects"
	Filter       string   // Path prefix filter
	User         string
	Description  string
}

// RestoreOptions configures restore behavior
type RestoreOptions struct {
	BackupPath   string
	Overwrite    bool
	Filter       string // Path prefix filter
	User         string
	IncludeTypes []string
}

// ExportOptions configures export behavior
type ExportOptions struct {
	Format      string // "json", "encrypted-json", "tar", "tar.gz"
	OutputPath  string
	Pretty      bool
	Compress    bool
	Encrypt     bool
	User        string
	ItemType    string // "secret", "folder", "object"
	Paths       []string
	Recursive   bool
}

// ImportOptions configures import behavior
type ImportOptions struct {
	Format    string
	InputPath string
	Overwrite bool
	User      string
	DryRun    bool
}

// Backup creates a backup of the database
func (db *DB) Backup(opts BackupOptions) error {
	if opts.OutputPath == "" {
		return fmt.Errorf("output path is required")
	}

	// Default to all types
	if len(opts.IncludeTypes) == 0 {
		opts.IncludeTypes = []string{"secrets", "folders", "objects"}
	}

	items := make([]BackupItem, 0)
	var totalSize int64

	// Backup secrets
	if contains(opts.IncludeTypes, "secrets") {
		keys, _ := db.KeysPage(0, 100000)
		prefix := "secret:"
		if opts.Filter != "" {
			prefix = "secret:" + opts.Filter
		}

		for _, key := range keys {
			keyStr := string(key)
			if len(keyStr) < len(prefix) || keyStr[:len(prefix)] != prefix {
				continue
			}

			value, err := db.Get(key)
			if err != nil {
				continue
			}

			data := map[string]any{
				"key":   keyStr,
				"value": value,
			}

			jsonData, err := json.Marshal(data)
			if err != nil {
				return fmt.Errorf("failed to marshal secret: %w", err)
			}

			items = append(items, BackupItem{
				Type: "secret",
				Path: keyStr,
				Data: jsonData,
			})
			totalSize += int64(len(value))
		}
	}

	// Backup folders
	if contains(opts.IncludeTypes, "folders") {
		folders, err := db.ListFolders(opts.Filter, true)
		if err != nil {
			return fmt.Errorf("failed to list folders: %w", err)
		}
		for _, folder := range folders {
			data, err := json.Marshal(folder)
			if err != nil {
				return fmt.Errorf("failed to marshal folder: %w", err)
			}
			items = append(items, BackupItem{
				Type: "folder",
				Path: folder.Path,
				Data: data,
			})
			totalSize += int64(len(data))
		}
	}

	// Backup objects
	if contains(opts.IncludeTypes, "objects") {
		objects, err := db.ListObjects(ObjectListOptions{
			Prefix:    opts.Filter,
			Recursive: true,
			MaxKeys:   100000,
		})
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}
		for _, obj := range objects {
			objData, meta, err := db.GetObject(obj.Path, opts.User)
			if err != nil {
				fmt.Printf("Warning: failed to get object %s: %v\n", obj.Path, err)
				continue
			}

			itemData := map[string]any{
				"content":      objData,
				"content_type": obj.ContentType,
				"size":         obj.Size,
				"version_id":   obj.VersionID,
				"created_at":   obj.CreatedAt,
				"metadata":     meta,
			}

			data, err := json.Marshal(itemData)
			if err != nil {
				return fmt.Errorf("failed to marshal object: %w", err)
			}

			items = append(items, BackupItem{
				Type: "object",
				Path: obj.Path,
				Data: data,
			})
			totalSize += int64(len(objData))
		}
	}

	// Create backup metadata with security features
	itemsData, _ := json.Marshal(items)
	signature, err := db.createSignature(itemsData, opts.User)
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	// Get previous backup IDs for chain linking
	chainLinks := db.getBackupChainLinks(3) // Last 3 backups

	metadata := BackupMetadata{
		Version:        "1.0",
		CreatedAt:      time.Now(),
		DBPath:         db.path,
		Compressed:     opts.Compress,
		Encrypted:      opts.Encrypt,
		ItemCount:      len(items),
		TotalSize:      totalSize,
		User:           opts.User,
		Description:    opts.Description,
		Signature:      signature,
		ChainLinks:     chainLinks,
	}

	// Record audit trail
	auditRecord := AuditRecord{
		Operation: "backup",
		Type:      "full",
		User:      opts.User,
		FilePath:  opts.OutputPath,
		ItemCount: len(items),
		Success:   true,
		Signature: signature,
		Metadata: map[string]interface{}{
			"compressed":  opts.Compress,
			"item_types":  opts.IncludeTypes,
			"filter":      opts.Filter,
			"total_size":  totalSize,
		},
	}

	if err := db.recordAudit(auditRecord); err != nil {
		fmt.Printf("Warning: failed to record audit: %v\n", err)
	}

	metadata.AuditID = auditRecord.ID

	// Create backup file with integrity check
	return db.writeSecureBackup(opts.OutputPath, metadata, items, opts.Compress)
}

// Restore restores from a backup
func (db *DB) Restore(opts RestoreOptions) error {
	if opts.BackupPath == "" {
		return fmt.Errorf("backup path is required")
	}

	// Verify backup integrity first
	fmt.Println("🔐 Verifying backup integrity...")
	verifiedMeta, err := db.VerifyBackupIntegrity(opts.BackupPath)
	if err != nil {
		auditRecord := AuditRecord{
			Operation: "restore",
			Type:      "full",
			User:      opts.User,
			FilePath:  opts.BackupPath,
			Success:   false,
			ErrorMsg:  fmt.Sprintf("Integrity verification failed: %v", err),
		}
		db.recordAudit(auditRecord)
		return fmt.Errorf("backup integrity verification failed: %w", err)
	}

	fmt.Printf("✓ Backup verified: signed by %s at %s\n",
		verifiedMeta.Signature.SignedBy,
		verifiedMeta.Signature.SignedAt.Format(time.RFC3339))

	if verifiedMeta.Signature.Fingerprint != "" {
		fmt.Printf("✓ Device fingerprint: %s\n", verifiedMeta.Signature.Fingerprint[:16]+"...")
	}

	if len(verifiedMeta.ChainLinks) > 0 {
		fmt.Printf("✓ Chain verified: %d previous backup(s)\n", len(verifiedMeta.ChainLinks))
	}

	metadata, items, err := db.readBackup(opts.BackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	fmt.Printf("\nRestoring backup created at %s (%d items)\n", metadata.CreatedAt.Format(time.RFC3339), len(items))

	restored := 0
	skipped := 0
	errors := 0

	for _, item := range items {
		// Apply filter if specified
		if opts.Filter != "" && !filepath.HasPrefix(item.Path, opts.Filter) {
			skipped++
			continue
		}

		// Check type filter
		if len(opts.IncludeTypes) > 0 && !contains(opts.IncludeTypes, item.Type+"s") {
			skipped++
			continue
		}

		// Restore item based on type
		switch item.Type {
		case "secret":
			var secretData map[string]any
			if err := json.Unmarshal(item.Data, &secretData); err != nil {
				fmt.Printf("Warning: failed to unmarshal secret %s: %v\n", item.Path, err)
				errors++
				continue
			}

			key := secretData["key"].(string)
			value := secretData["value"].(string)

			// Check if exists
			if !opts.Overwrite {
				if _, err := db.Get([]byte(key)); err == nil {
					skipped++
					continue
				}
			}

			if err := db.Put([]byte(key), []byte(value)); err != nil {
				fmt.Printf("Warning: failed to restore secret %s: %v\n", item.Path, err)
				errors++
				continue
			}
			restored++

		case "folder":
			var folder FolderMetadata
			if err := json.Unmarshal(item.Data, &folder); err != nil {
				fmt.Printf("Warning: failed to unmarshal folder %s: %v\n", item.Path, err)
				errors++
				continue
			}

			// Check if exists
			if !opts.Overwrite {
				if _, err := db.GetFolder(folder.Path); err == nil {
					skipped++
					continue
				}
			}

			if err := db.CreateFolder(folder.Path, opts.User); err != nil {
				fmt.Printf("Warning: failed to restore folder %s: %v\n", item.Path, err)
				errors++
				continue
			}
			restored++

		case "object":
			var objData map[string]any
			if err := json.Unmarshal(item.Data, &objData); err != nil {
				fmt.Printf("Warning: failed to unmarshal object %s: %v\n", item.Path, err)
				errors++
				continue
			}

			contentBytes, ok := objData["content"].(string)
			if !ok {
				// Try as byte array
				if contentArr, ok := objData["content"].([]any); ok {
					content := make([]byte, len(contentArr))
					for i, v := range contentArr {
						content[i] = byte(v.(float64))
					}
					contentBytes = string(content)
				}
			}

			content := []byte(contentBytes)
			contentType, _ := objData["content_type"].(string)
			metadata, _ := objData["metadata"].(map[string]any)

			customMeta := make(map[string]string)
			for k, v := range metadata {
				if strVal, ok := v.(string); ok {
					customMeta[k] = strVal
				}
			}

			// Check if exists
			if !opts.Overwrite {
				if _, _, err := db.GetObject(item.Path, opts.User); err == nil {
					skipped++
					continue
				}
			}

			objOpts := &ObjectOptions{
				CustomMetadata: customMeta,
				Encrypt:        true,
			}

			if _, err := db.StoreObject(item.Path, contentType, opts.User, content, objOpts); err != nil {
				fmt.Printf("Warning: failed to restore object %s: %v\n", item.Path, err)
				errors++
				continue
			}
			restored++

		default:
			fmt.Printf("Warning: unknown item type: %s\n", item.Type)
			errors++
		}
	}

	fmt.Printf("Restore complete: %d restored, %d skipped, %d errors\n", restored, skipped, errors)

	// Record audit trail
	auditRecord := AuditRecord{
		Operation: "restore",
		Type:      "full",
		User:      opts.User,
		FilePath:  opts.BackupPath,
		ItemCount: restored,
		Success:   errors == 0,
		Signature: metadata.Signature,
		Metadata: map[string]interface{}{
			"restored": restored,
			"skipped":  skipped,
			"errors":   errors,
			"overwrite": opts.Overwrite,
			"source_backup_id": metadata.AuditID,
		},
	}
	if errors > 0 {
		auditRecord.ErrorMsg = fmt.Sprintf("%d errors during restore", errors)
	}

	if err := db.recordAudit(auditRecord); err != nil {
		fmt.Printf("Warning: failed to record audit: %v\n", err)
	}

	return nil
}

// Export exports items to a file
func (db *DB) Export(opts ExportOptions) error {
	if opts.OutputPath == "" {
		return fmt.Errorf("output path is required")
	}

	items := make([]map[string]any, 0)

	// Export based on paths or type
	for _, path := range opts.Paths {
		switch opts.ItemType {
		case "secret":
			value, err := db.Get([]byte(path))
			if err != nil {
				return fmt.Errorf("failed to get secret %s: %w", path, err)
			}
			items = append(items, map[string]any{
				"type": "secret",
				"path": path,
				"data": map[string]any{
					"key":   path,
					"value": string(value),
				},
			})

		case "folder":
			folder, err := db.GetFolder(path)
			if err != nil {
				return fmt.Errorf("failed to get folder %s: %w", path, err)
			}
			items = append(items, map[string]any{
				"type": "folder",
				"path": path,
				"data": folder,
			})

			// If recursive, export objects in folder
			if opts.Recursive {
				prefix := path
				if prefix[0] == '/' {
					prefix = prefix[1:]
				}
				if prefix != "" && prefix[len(prefix)-1] != '/' {
					prefix += "/"
				}

				objects, err := db.ListObjects(ObjectListOptions{
					Prefix:    prefix,
					Recursive: true,
					MaxKeys:   10000,
				})
				if err != nil {
					return fmt.Errorf("failed to list objects in folder: %w", err)
				}

				for _, obj := range objects {
					objData, _, err := db.GetObject(obj.Path, opts.User)
					if err != nil {
						fmt.Printf("Warning: failed to get object %s: %v\n", obj.Path, err)
						continue
					}
					items = append(items, map[string]any{
						"type": "object",
						"path": obj.Path,
						"data": map[string]any{
							"content":      objData,
							"content_type": obj.ContentType,
							"size":         obj.Size,
						},
					})
				}
			}

		case "object":
			objData, meta, err := db.GetObject(path, opts.User)
			if err != nil {
				return fmt.Errorf("failed to get object %s: %w", path, err)
			}
			items = append(items, map[string]any{
				"type": "object",
				"path": path,
				"data": map[string]any{
					"content":      objData,
					"content_type": meta.ContentType,
					"size":         meta.Size,
				},
			})

		default:
			return fmt.Errorf("unknown item type: %s", opts.ItemType)
		}
	}

	// Write export file based on format
	var exportErr error
	switch opts.Format {
	case "json", "encrypted-json":
		exportErr = db.exportJSON(opts.OutputPath, items, opts.Pretty, opts.Format == "encrypted-json")
	case "tar", "tar.gz":
		exportErr = db.exportTar(opts.OutputPath, items, opts.Format == "tar.gz")
	default:
		exportErr = fmt.Errorf("unsupported format: %s", opts.Format)
	}

	// Record audit trail
	auditRecord := AuditRecord{
		Operation: "export",
		Type:      opts.ItemType,
		User:      opts.User,
		FilePath:  opts.OutputPath,
		ItemCount: len(items),
		Success:   exportErr == nil,
		Metadata: map[string]interface{}{
			"format":    opts.Format,
			"paths":     opts.Paths,
			"recursive": opts.Recursive,
		},
	}

	if exportErr != nil {
		auditRecord.ErrorMsg = exportErr.Error()
	}

	if err := db.recordAudit(auditRecord); err != nil {
		fmt.Printf("Warning: failed to record audit: %v\n", err)
	}

	return exportErr
}

// Import imports items from a file
func (db *DB) Import(opts ImportOptions) error {
	if opts.InputPath == "" {
		return fmt.Errorf("input path is required")
	}

	var items []map[string]any
	var err error

	switch opts.Format {
	case "json", "encrypted-json":
		items, err = db.importJSON(opts.InputPath, opts.Format == "encrypted-json")
	case "tar", "tar.gz":
		items, err = db.importTar(opts.InputPath, opts.Format == "tar.gz")
	default:
		// Try to auto-detect format
		items, err = db.autoDetectImport(opts.InputPath)
	}

	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	if opts.DryRun {
		fmt.Printf("DRY RUN: Would import %d items\n", len(items))
		for _, item := range items {
			fmt.Printf("  - %s: %s\n", item["type"], item["path"])
		}
		return nil
	}

	imported := 0
	skipped := 0
	errors := 0

	for _, item := range items {
		itemType, _ := item["type"].(string)
		path, _ := item["path"].(string)
		data := item["data"]

		switch itemType {
		case "secret":
			if !opts.Overwrite {
				if _, err := db.Get([]byte(path)); err == nil {
					skipped++
					continue
				}
			}

			var secretData map[string]any
			dataBytes, _ := json.Marshal(data)
			if err := json.Unmarshal(dataBytes, &secretData); err != nil {
				fmt.Printf("Warning: failed to unmarshal secret %s: %v\n", path, err)
				errors++
				continue
			}

			key := secretData["key"].(string)
			value := secretData["value"].(string)

			if err := db.Put([]byte(key), []byte(value)); err != nil {
				fmt.Printf("Warning: failed to import secret %s: %v\n", path, err)
				errors++
				continue
			}
			imported++

		case "folder":
			if !opts.Overwrite {
				if _, err := db.GetFolder(path); err == nil {
					skipped++
					continue
				}
			}

			if err := db.CreateFolder(path, opts.User); err != nil {
				fmt.Printf("Warning: failed to import folder %s: %v\n", path, err)
				errors++
				continue
			}
			imported++

		case "object":
			if !opts.Overwrite {
				if _, _, err := db.GetObject(path, opts.User); err == nil {
					skipped++
					continue
				}
			}

			objData, ok := data.(map[string]any)
			if !ok {
				fmt.Printf("Warning: invalid object data for %s\n", path)
				errors++
				continue
			}

			contentStr, _ := objData["content"].(string)
			content := []byte(contentStr)
			contentType, _ := objData["content_type"].(string)

			objOpts := &ObjectOptions{
				Encrypt: true,
			}

			if _, err := db.StoreObject(path, contentType, opts.User, content, objOpts); err != nil {
				fmt.Printf("Warning: failed to import object %s: %v\n", path, err)
				errors++
				continue
			}
			imported++

		default:
			fmt.Printf("Warning: unknown item type: %s\n", itemType)
			errors++
		}
	}

	fmt.Printf("Import complete: %d imported, %d skipped, %d errors\n", imported, skipped, errors)

	// Record audit trail
	auditRecord := AuditRecord{
		Operation: "import",
		Type:      "file",
		User:      opts.User,
		FilePath:  opts.InputPath,
		ItemCount: imported,
		Success:   errors == 0,
		Metadata: map[string]interface{}{
			"imported":  imported,
			"skipped":   skipped,
			"errors":    errors,
			"overwrite": opts.Overwrite,
			"format":    opts.Format,
		},
	}
	if errors > 0 {
		auditRecord.ErrorMsg = fmt.Sprintf("%d errors during import", errors)
	}

	if err := db.recordAudit(auditRecord); err != nil {
		fmt.Printf("Warning: failed to record audit: %v\n", err)
	}

	return nil
}

// Helper functions

// writeSecureBackup writes backup with integrity checks and signatures
func (db *DB) writeSecureBackup(path string, metadata BackupMetadata, items []BackupItem, compress bool) error {
	backup := map[string]any{
		"metadata": metadata,
		"items":    items,
	}

	// Serialize backup
	data, err := json.Marshal(backup)
	if err != nil {
		return fmt.Errorf("failed to encode backup: %w", err)
	}

	// Calculate integrity check for entire file
	metadata.IntegrityCheck = hashData(data)

	// Update backup with integrity check
	backup["metadata"] = metadata
	data, err = json.Marshal(backup)
	if err != nil {
		return fmt.Errorf("failed to encode backup: %w", err)
	}

	// Write to file
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	var writer io.Writer = f

	if compress {
		gzWriter := gzip.NewWriter(f)
		defer gzWriter.Close()
		writer = gzWriter
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	// Store backup reference for chain linking
	db.storeBackupReference(metadata.AuditID, path)

	return nil
}

func (db *DB) writeBackup(path string, metadata BackupMetadata, items []BackupItem, compress, encrypt bool) error {
	// Use secure backup method
	return db.writeSecureBackup(path, metadata, items, compress)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	var writer io.Writer = f

	if compress {
		gzWriter := gzip.NewWriter(f)
		defer gzWriter.Close()
		writer = gzWriter
	}

	// Note: Backup data is already encrypted at the object level
	// Additional encryption can be added here if needed

	backup := map[string]any{
		"metadata": metadata,
		"items":    items,
	}

	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(backup); err != nil {
		return fmt.Errorf("failed to encode backup: %w", err)
	}

	return nil
}

func (db *DB) readBackup(path string) (BackupMetadata, []BackupItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return BackupMetadata{}, nil, fmt.Errorf("failed to open backup file: %w", err)
	}
	defer f.Close()

	var reader io.Reader = f

	// Try gzip decompression
	gzReader, err := gzip.NewReader(f)
	if err == nil {
		defer gzReader.Close()
		reader = gzReader
	} else {
		f.Seek(0, 0) // Reset if not gzip
	}

	var backup map[string]json.RawMessage
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&backup); err != nil {
		return BackupMetadata{}, nil, fmt.Errorf("failed to decode backup: %w", err)
	}

	var metadata BackupMetadata
	if err := json.Unmarshal(backup["metadata"], &metadata); err != nil {
		return BackupMetadata{}, nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	var items []BackupItem
	if err := json.Unmarshal(backup["items"], &items); err != nil {
		return BackupMetadata{}, nil, fmt.Errorf("failed to unmarshal items: %w", err)
	}

	return metadata, items, nil
}

func (db *DB) exportJSON(path string, items []map[string]any, pretty, encrypt bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	if pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(map[string]any{
		"version":    "1.0",
		"exported_at": time.Now(),
		"items":      items,
	})
}

func (db *DB) importJSON(path string, encrypted bool) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data map[string]any
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	items, ok := data["items"].([]any)
	if !ok {
		return nil, fmt.Errorf("invalid import format: missing items array")
	}

	result := make([]map[string]any, len(items))
	for i, item := range items {
		result[i], ok = item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid item format at index %d", i)
		}
	}

	return result, nil
}

func (db *DB) exportTar(path string, items []map[string]any, compress bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var writer io.Writer = f
	if compress {
		gzWriter := gzip.NewWriter(f)
		defer gzWriter.Close()
		writer = gzWriter
	}

	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	for _, item := range items {
		itemType, _ := item["type"].(string)
		path, _ := item["path"].(string)

		data, err := json.Marshal(item)
		if err != nil {
			return err
		}

		header := &tar.Header{
			Name:    fmt.Sprintf("%s/%s.json", itemType, path),
			Mode:    0644,
			Size:    int64(len(data)),
			ModTime: time.Now(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		if _, err := tarWriter.Write(data); err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) importTar(path string, compressed bool) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	if compressed {
		gzReader, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	tarReader := tar.NewReader(reader)
	items := make([]map[string]any, 0)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		data := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, data); err != nil {
			return nil, err
		}

		var item map[string]any
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	return items, nil
}

func (db *DB) autoDetectImport(path string) ([]map[string]any, error) {
	// Try JSON first
	items, err := db.importJSON(path, false)
	if err == nil {
		return items, nil
	}

	// Try compressed tar
	items, err = db.importTar(path, true)
	if err == nil {
		return items, nil
	}

	// Try uncompressed tar
	items, err = db.importTar(path, false)
	if err == nil {
		return items, nil
	}

	return nil, fmt.Errorf("could not detect import format")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

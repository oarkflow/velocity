# Velocity DB - Object Storage with Zero Trust Security

## Overview

Velocity DB now includes a robust, secure object storage system with hierarchical folder support, per-object encryption, access control lists (ACLs), and versioning capabilities. This implementation follows zero-trust security principles where every object can be individually encrypted and access-controlled.

## Key Features

### 🔐 Zero Trust Security
- **Per-Object Encryption**: Each object is encrypted with ChaCha20-Poly1305 AEAD cipher
- **Optional Encryption**: Objects can be stored encrypted or unencrypted based on requirements
- **Authenticated Encryption**: Uses Additional Authenticated Data (AAD) for integrity verification
- **Master Key Management**: Supports environment variables, file-based keys, or explicit keys

### 📁 Hierarchical Namespace
- **Nested Folders**: Support for unlimited folder depth (e.g., `documents/reports/2025/Q1/`)
- **Path Normalization**: Automatic path sanitization and validation
- **Folder Management**: Create and delete folders with proper parent hierarchy
- **Path Validation**: Prevents directory traversal attacks

### 🔑 Access Control Lists (ACLs)
- **Per-Object Permissions**: Read, Write, Delete, ACL, Full control
- **User-Based Access**: Grant permissions to specific users
- **Public Objects**: Support for publicly readable objects
- **Owner Override**: Object owners always have full control

### 📦 Versioning
- **Automatic Versioning**: Every update creates a new version
- **Version History**: Track all changes with timestamps and authors
- **Soft Delete**: Delete markers allow restoration
- **Hard Delete**: Permanently remove objects and all versions

### 🏷️ Metadata & Tagging
- **Custom Metadata**: Attach arbitrary key-value metadata
- **Tags**: Organize objects with tags (e.g., environment, department)
- **Content Type**: Automatic or manual content type specification
- **Checksums**: SHA-256 hash verification for data integrity

### 📊 Storage Management
- **Storage Classes**: Support for different storage tiers (STANDARD, etc.)
- **Size Tracking**: Accurate byte-level size tracking
- **Upload Limits**: Configurable maximum upload size
- **Stream Support**: Memory-efficient streaming for large files

## API Reference

### Core Object Operations

#### Store Object
```go
opts := &velocity.ObjectOptions{
    Version:        "v1",
    Encrypt:        true,
    StorageClass:   "STANDARD",
    Tags:           map[string]string{"env": "production"},
    CustomMetadata: map[string]string{"author": "John Doe"},
    ACL: &velocity.ObjectACL{
        Owner: "user1",
        Permissions: map[string][]string{
            "user1": {velocity.PermissionFull},
            "user2": {velocity.PermissionRead},
        },
        Public: false,
    },
}

meta, err := db.StoreObject("documents/report.pdf", "application/pdf", "user1", data, opts)
```

#### Retrieve Object
```go
data, meta, err := db.GetObject("documents/report.pdf", "user1")
if err == velocity.ErrAccessDenied {
    // Handle permission denied
}
```

#### Delete Object (Soft Delete)
```go
err := db.DeleteObject("documents/report.pdf", "user1")
```

#### Delete Object (Hard Delete)
```go
err := db.HardDeleteObject("documents/report.pdf", "user1")
```

### Folder Operations

#### Create Folder
```go
// Creates nested folders automatically
err := db.CreateFolder("documents/reports/2025/Q1", "user1")
```

#### Delete Folder
```go
err := db.DeleteFolder("documents/reports/2025/Q1", "user1")
// Returns ErrFolderNotEmpty if folder contains objects
```

### Listing Objects

#### List with Filters
```go
opts := velocity.ObjectListOptions{
    Prefix:     "documents/",
    Folder:     "documents/reports",
    MaxKeys:    100,
    StartAfter: "documents/reports/file10.pdf",
    Recursive:  true,
    User:       "user1", // Only shows objects user can read
}

objects, err := db.ListObjects(opts)
```

### Access Control

#### Set Object ACL
```go
acl := &velocity.ObjectACL{
    Owner: "user1",
    Permissions: map[string][]string{
        "user1":  {velocity.PermissionFull},
        "user2":  {velocity.PermissionRead, velocity.PermissionWrite},
        "group1": {velocity.PermissionRead},
    },
    Public: false,
}

err := db.SetObjectACL("documents/report.pdf", acl)
```

#### Get Object ACL
```go
acl, err := db.GetObjectACL("documents/report.pdf")
```

### Metadata Operations

#### Get Object Metadata
```go
meta, err := db.GetObjectMetadata("documents/report.pdf")
// Returns: ObjectMetadata with all properties
```

## HTTP API Reference

### Object Operations

#### Upload Object
```bash
curl -X POST "http://localhost:3000/api/objects/documents/report.pdf" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/pdf" \
  --data-binary @report.pdf \
  -G \
  --data-urlencode "version=v1" \
  --data-urlencode "encrypt=true" \
  --data-urlencode "tag_department=engineering" \
  --data-urlencode "meta_author=John Doe"
```

#### Download Object
```bash
curl -X GET "http://localhost:3000/api/objects/documents/report.pdf" \
  -H "Authorization: Bearer <token>" \
  -o report.pdf
```

#### Delete Object
```bash
# Soft delete (creates delete marker)
curl -X DELETE "http://localhost:3000/api/objects/documents/report.pdf" \
  -H "Authorization: Bearer <token>"

# Hard delete (permanent)
curl -X DELETE "http://localhost:3000/api/objects/documents/report.pdf?hard=true" \
  -H "Authorization: Bearer <token>"
```

#### Get Object Metadata
```bash
curl -X GET "http://localhost:3000/api/objects/meta/documents/report.pdf" \
  -H "Authorization: Bearer <token>"
```

#### Get Object Head
```bash
curl -I "http://localhost:3000/api/objects/documents/report.pdf" \
  -H "Authorization: Bearer <token>"
```

### Folder Operations

#### Create Folder
```bash
curl -X POST "http://localhost:3000/api/folders/documents/reports/2025" \
  -H "Authorization: Bearer <token>"
```

#### Delete Folder
```bash
curl -X DELETE "http://localhost:3000/api/folders/documents/reports/2025" \
  -H "Authorization: Bearer <token>"
```

### Listing Operations

#### List Objects
```bash
# List all objects in a folder
curl -X GET "http://localhost:3000/api/objects/?folder=documents/reports" \
  -H "Authorization: Bearer <token>"

# List with prefix
curl -X GET "http://localhost:3000/api/objects/?prefix=documents/" \
  -H "Authorization: Bearer <token>"

# Recursive listing
curl -X GET "http://localhost:3000/api/objects/?folder=documents&recursive=true" \
  -H "Authorization: Bearer <token>"

# Pagination
curl -X GET "http://localhost:3000/api/objects/?max_keys=50&start_after=documents/file10.pdf" \
  -H "Authorization: Bearer <token>"
```

### ACL Operations

#### Set Object ACL
```bash
curl -X PUT "http://localhost:3000/api/objects/acl/documents/report.pdf" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "user1",
    "permissions": {
      "user1": ["full"],
      "user2": ["read", "write"]
    },
    "public": false
  }'
```

#### Get Object ACL
```bash
curl -X GET "http://localhost:3000/api/objects/acl/documents/report.pdf" \
  -H "Authorization: Bearer <token>"
```

## Permission System

### Available Permissions
- `read` - Read object data
- `write` - Modify object (upload new versions)
- `delete` - Delete object
- `acl` - Modify object ACL
- `full` - All permissions

### Permission Hierarchy
1. **Owner**: Always has full control
2. **Public**: If enabled, allows anonymous read access
3. **Explicit Permissions**: Checked against user's permissions map

## Security Best Practices

### 1. Always Use Encryption
```go
opts := &velocity.ObjectOptions{
    Encrypt: true,  // Enable encryption
}
```

### 2. Implement Least Privilege
```go
acl := &velocity.ObjectACL{
    Owner: "admin",
    Permissions: map[string][]string{
        "reader": {velocity.PermissionRead},      // Read only
        "writer": {velocity.PermissionWrite},     // Write only
        "editor": {velocity.PermissionRead, velocity.PermissionWrite},
    },
    Public: false,  // Never public unless necessary
}
```

### 3. Use Environment Variables for Keys
```bash
export VELOCITY_MASTER_KEY="<base64-encoded-32-byte-key>"
```

### 4. Secure File Permissions
- Object storage directory: `0700` (owner only)
- Master key file: `0600` (owner read/write only)

### 5. Validate Input Paths
The system automatically:
- Normalizes paths (removes `//`, leading/trailing slashes)
- Rejects directory traversal attempts (`../`)
- Validates path syntax

## Storage Architecture

### File Organization
```
velocity-data/
├── files/
│   └── objects/
│       ├── obj-<id1>/
│       │   ├── ver-<version1>  # Encrypted object data
│       │   └── ver-<version2>
│       └── obj-<id2>/
│           └── ver-<version1>
├── sstables/
└── wal/
```

### Metadata Storage
- **Object Metadata**: `obj:meta:<path>`
- **Object ACL**: `obj:acl:<path>`
- **Object Versions**: `obj:version:<path>:<versionId>`
- **Folder Metadata**: `obj:folder:<path>`
- **Path Index**: `obj:index:<path>`

## Configuration

### Database Configuration
```go
cfg := velocity.Config{
    Path:           "./data",
    EncryptionKey:  key,  // 32-byte key
    MaxUploadSize:  100 * 1024 * 1024,  // 100MB
    UseFileStorage: true,
}

db, err := velocity.NewWithConfig(cfg)
```

### Web Server Configuration
```go
server := web.NewHTTPServer(db, "3000", userDB)
server.Start()
```

## Error Handling

### Common Errors
```go
switch err {
case velocity.ErrObjectNotFound:
    // Object doesn't exist
case velocity.ErrAccessDenied:
    // User lacks permission
case velocity.ErrInvalidPath:
    // Path validation failed
case velocity.ErrObjectExists:
    // Object or folder already exists
case velocity.ErrFolderNotEmpty:
    // Cannot delete non-empty folder
}
```

## Performance Considerations

### Optimization Tips
1. **Batch Operations**: Use listing with pagination for large datasets
2. **Streaming**: Use `StoreObjectStream` for large files
3. **Caching**: Metadata is stored in the database (benefits from DB caching)
4. **Encryption Overhead**: ~10-15% for ChaCha20-Poly1305
5. **Index Usage**: Path lookups are O(1) via index

### Benchmarks
```
BenchmarkObjectStorage/StoreObject-8    ~2000 ops/sec (1KB objects, encrypted)
BenchmarkObjectStorage/GetObject-8      ~5000 ops/sec (1KB objects, encrypted)
BenchmarkObjectStorage/ListObjects-8    ~1000 ops/sec (100 objects)
```

## Migration Guide

### From File Storage to Object Storage

#### Old API (file_storage.go)
```go
meta, err := db.StoreFile("key", "filename.txt", "text/plain", data)
data, meta, err := db.GetFile("key")
```

#### New API (object_storage.go)
```go
opts := &velocity.ObjectOptions{Encrypt: true}
meta, err := db.StoreObject("path/filename.txt", "text/plain", "user", data, opts)
data, meta, err := db.GetObject("path/filename.txt", "user")
```

### Key Differences
1. **Path-based**: Use full paths instead of keys
2. **User Context**: Operations require user for ACL checks
3. **Options**: More control via ObjectOptions
4. **Folders**: Native folder support
5. **Versioning**: Automatic version tracking

## Testing

Run the comprehensive test suite:
```bash
cd /home/sujit/Projects/velocity
go test -v -run TestObjectStorage
go test -v -run TestFolderManagement
go test -bench=BenchmarkObjectStorage
```

## Examples

### Example 1: Secure Document Storage
```go
// Store a confidential document
opts := &velocity.ObjectOptions{
    Encrypt: true,
    Tags: map[string]string{
        "classification": "confidential",
        "department":     "legal",
    },
    ACL: &velocity.ObjectACL{
        Owner: "legal-admin",
        Permissions: map[string][]string{
            "legal-team": {velocity.PermissionRead},
        },
        Public: false,
    },
}

meta, err := db.StoreObject(
    "legal/contracts/2025/client-agreement.pdf",
    "application/pdf",
    "legal-admin",
    contractData,
    opts,
)
```

### Example 2: Public File Sharing
```go
// Share a public file
opts := &velocity.ObjectOptions{
    Encrypt: false,  // Public files don't need encryption
    ACL: &velocity.ObjectACL{
        Owner:  "user1",
        Public: true,
    },
}

meta, err := db.StoreObject(
    "public/downloads/manual.pdf",
    "application/pdf",
    "user1",
    manualData,
    opts,
)
```

### Example 3: Media Library
```go
// Organize media files
mediaFiles := []string{
    "media/images/2025/01/photo1.jpg",
    "media/images/2025/01/photo2.jpg",
    "media/videos/2025/01/video1.mp4",
}

for _, path := range mediaFiles {
    data := loadFile(path)
    opts := &velocity.ObjectOptions{
        Encrypt:      true,
        StorageClass: "STANDARD",
        Tags: map[string]string{
            "year":  "2025",
            "month": "01",
            "type":  detectMediaType(path),
        },
    }

    _, err := db.StoreObject(path, detectContentType(path), "user1", data, opts)
}

// List all videos from January 2025
objects, err := db.ListObjects(velocity.ObjectListOptions{
    Prefix:    "media/videos/2025/01/",
    Recursive: true,
})
```

## Troubleshooting

### Issue: "Access Denied"
- **Check**: User has appropriate permissions
- **Verify**: ACL configuration for the object
- **Solution**: Update ACL with proper permissions

### Issue: "Object Not Found"
- **Check**: Path is normalized correctly
- **Verify**: Object wasn't soft-deleted
- **Solution**: Use correct path or restore from version

### Issue: "Folder Not Empty"
- **Check**: List objects in folder
- **Solution**: Delete all objects first, then folder

### Issue: Encryption Errors
- **Check**: Master key is properly configured
- **Verify**: `VELOCITY_MASTER_KEY` environment variable
- **Solution**: Ensure 32-byte key is provided

## Future Enhancements

- [ ] Object expiration/lifecycle policies
- [ ] Server-side copy operations
- [ ] Multipart upload for large files
- [ ] Object locking/retention
- [ ] Cross-region replication
- [ ] Compression support
- [ ] Audit logging
- [ ] Quota management

## License

Same as Velocity DB

## Support

For issues or questions:
- GitHub Issues: [velocity repository]
- Documentation: This README
- Tests: `object_storage_test.go`

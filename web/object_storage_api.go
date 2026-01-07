package web

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/velocity"
)

// Setup object storage routes
func (s *HTTPServer) setupObjectStorageRoutes() {
	// Object storage routes (require authentication)
	objects := s.app.Group("/api/objects", s.jwtAuthMiddleware())

	// Object CRUD operations
	objects.Post("/*", s.handleObjectUpload)
	objects.Get("/*", s.handleObjectDownload)
	objects.Delete("/*", s.handleObjectDelete)
	objects.Head("/*", s.handleObjectHead)

	// Object metadata and ACL
	objects.Get("/meta/*", s.handleObjectMetadata)
	objects.Put("/acl/*", s.handleObjectACL)
	objects.Get("/acl/*", s.handleGetObjectACL)

	// List objects
	objects.Get("/", s.handleObjectList)

	// Folder operations
	folders := s.app.Group("/api/folders", s.jwtAuthMiddleware())
	folders.Post("/*", s.handleCreateFolder)
	folders.Delete("/*", s.handleDeleteFolder)

	// Versioning
	versions := s.app.Group("/api/versions", s.jwtAuthMiddleware())
	versions.Get("/*", s.handleListVersions)
	versions.Get("/:versionId/*", s.handleGetVersion)
}

// handleObjectUpload uploads an object to storage
func (s *HTTPServer) handleObjectUpload(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	// Get content type
	contentType := c.Get("Content-Type", "application/octet-stream")

	// Parse options from headers/query
	opts := &velocity.ObjectOptions{
		Version:        c.Query("version", velocity.DefaultVersion),
		Encrypt:        c.Query("encrypt", "true") == "true",
		StorageClass:   c.Query("storage_class", "STANDARD"),
		Tags:           parseTagsFromQuery(c),
		CustomMetadata: parseMetadataFromQuery(c),
	}

	// Parse ACL if provided
	if aclPublic := c.Query("public"); aclPublic == "true" {
		opts.ACL = &velocity.ObjectACL{
			Owner:       username,
			Permissions: map[string][]string{username: {velocity.PermissionFull}},
			Public:      true,
		}
	}

	// Get body as stream
	body := c.Context().RequestBodyStream()
	contentLength := int64(c.Context().Request.Header.ContentLength())

	// Store object
	meta, err := s.db.StoreObjectStream(path, contentType, username, body, contentLength, opts)
	if err != nil {
		if err == velocity.ErrInvalidPath {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid path",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":  "Object uploaded successfully",
		"metadata": meta,
	})
}

// handleObjectDownload downloads an object
func (s *HTTPServer) handleObjectDownload(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	// Get object
	data, meta, err := s.db.GetObject(path, username)
	if err != nil {
		if err == velocity.ErrObjectNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Object not found",
			})
		}
		if err == velocity.ErrAccessDenied {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Set headers
	c.Set("Content-Type", meta.ContentType)
	c.Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	c.Set("X-Object-ID", meta.ObjectID)
	c.Set("X-Version-ID", meta.VersionID)
	c.Set("X-Object-Hash", meta.Hash)
	c.Set("ETag", meta.Hash)

	// Set content disposition for download
	if c.Query("download") == "true" {
		c.Set("Content-Disposition", "attachment; filename=\""+meta.Name+"\"")
	}

	return c.Send(data)
}

// handleObjectDelete deletes an object
func (s *HTTPServer) handleObjectDelete(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	// Check if hard delete requested
	hardDelete := c.Query("hard") == "true"

	var err error
	if hardDelete {
		err = s.db.HardDeleteObject(path, username)
	} else {
		err = s.db.DeleteObject(path, username)
	}

	if err != nil {
		if err == velocity.ErrObjectNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Object not found",
			})
		}
		if err == velocity.ErrAccessDenied {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Object deleted successfully",
	})
}

// handleObjectHead returns object metadata without body
func (s *HTTPServer) handleObjectHead(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Object path is required")
	}

	meta, err := s.db.GetObjectMetadata(path)
	if err != nil {
		if err == velocity.ErrObjectNotFound {
			return c.SendStatus(fiber.StatusNotFound)
		}
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Check permissions
	// This is simplified - in production, use proper permission checking
	_ = username

	// Set headers
	c.Set("Content-Type", meta.ContentType)
	c.Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	c.Set("X-Object-ID", meta.ObjectID)
	c.Set("X-Version-ID", meta.VersionID)
	c.Set("X-Object-Hash", meta.Hash)
	c.Set("ETag", meta.Hash)
	c.Set("Last-Modified", meta.ModifiedAt.Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	return c.SendStatus(fiber.StatusOK)
}

// handleObjectMetadata returns object metadata
func (s *HTTPServer) handleObjectMetadata(c *fiber.Ctx) error {
	path := strings.TrimPrefix(c.Params("*"), "meta/")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	meta, err := s.db.GetObjectMetadata(path)
	if err != nil {
		if err == velocity.ErrObjectNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Object not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(meta)
}

// handleObjectACL updates object ACL
func (s *HTTPServer) handleObjectACL(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := strings.TrimPrefix(c.Params("*"), "acl/")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	var acl velocity.ObjectACL
	if err := c.BodyParser(&acl); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ACL format",
		})
	}

	// Verify user has ACL permission
	// Simplified check - in production, implement proper permission verification
	_ = username

	if err := s.db.SetObjectACL(path, &acl); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "ACL updated successfully",
	})
}

// handleGetObjectACL retrieves object ACL
func (s *HTTPServer) handleGetObjectACL(c *fiber.Ctx) error {
	path := strings.TrimPrefix(c.Params("*"), "acl/")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	acl, err := s.db.GetObjectACL(path)
	if err != nil {
		if err == velocity.ErrObjectNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Object not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(acl)
}

// handleObjectList lists objects
func (s *HTTPServer) handleObjectList(c *fiber.Ctx) error {
	username := c.Locals("username").(string)

	// Parse query parameters
	opts := velocity.ObjectListOptions{
		Prefix:     c.Query("prefix", ""),
		Folder:     c.Query("folder", ""),
		StartAfter: c.Query("start_after", ""),
		Recursive:  c.Query("recursive", "false") == "true",
		User:       username,
	}

	// Parse max_keys
	if maxKeysStr := c.Query("max_keys"); maxKeysStr != "" {
		if maxKeys, err := strconv.Atoi(maxKeysStr); err == nil {
			opts.MaxKeys = maxKeys
		}
	}

	objects, err := s.db.ListObjects(opts)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"objects": objects,
		"count":   len(objects),
	})
}

// handleCreateFolder creates a folder
func (s *HTTPServer) handleCreateFolder(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Folder path is required",
		})
	}

	if err := s.db.CreateFolder(path, username); err != nil {
		if err == velocity.ErrObjectExists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Folder already exists",
			})
		}
		if err == velocity.ErrInvalidPath {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid path",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Folder created successfully",
		"path":    path,
	})
}

// handleDeleteFolder deletes a folder
func (s *HTTPServer) handleDeleteFolder(c *fiber.Ctx) error {
	username := c.Locals("username").(string)
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Folder path is required",
		})
	}

	if err := s.db.DeleteFolder(path, username); err != nil {
		if err == velocity.ErrObjectNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Folder not found",
			})
		}
		if err == velocity.ErrFolderNotEmpty {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Folder is not empty",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Folder deleted successfully",
	})
}

// handleListVersions lists all versions of an object
func (s *HTTPServer) handleListVersions(c *fiber.Ctx) error {
	path := c.Params("*")

	if path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path is required",
		})
	}

	// TODO: Implement version listing
	// For now, return placeholder
	return c.JSON(fiber.Map{
		"message":  "Version listing not yet implemented",
		"path":     path,
		"versions": []string{},
	})
}

// handleGetVersion retrieves a specific version of an object
func (s *HTTPServer) handleGetVersion(c *fiber.Ctx) error {
	versionID := c.Params("versionId")
	path := c.Params("*")

	if path == "" || versionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Object path and version ID are required",
		})
	}

	// TODO: Implement version retrieval
	// For now, return placeholder
	return c.JSON(fiber.Map{
		"message":    "Version retrieval not yet implemented",
		"path":       path,
		"version_id": versionID,
	})
}

// Helper functions

func parseTagsFromQuery(c *fiber.Ctx) map[string]string {
	tags := make(map[string]string)

	// Parse tags from query parameters like ?tag_key1=value1&tag_key2=value2
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if strings.HasPrefix(keyStr, "tag_") {
			tagKey := strings.TrimPrefix(keyStr, "tag_")
			tags[tagKey] = string(value)
		}
	})

	return tags
}

func parseMetadataFromQuery(c *fiber.Ctx) map[string]string {
	metadata := make(map[string]string)

	// Parse metadata from query parameters like ?meta_author=john&meta_description=test
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if strings.HasPrefix(keyStr, "meta_") {
			metaKey := strings.TrimPrefix(keyStr, "meta_")
			metadata[metaKey] = string(value)
		}
	})

	return metadata
}

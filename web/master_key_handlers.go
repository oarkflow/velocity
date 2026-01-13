package web

import (
	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/velocity"
)

// handleGetMasterKeyConfig returns the current master key configuration
func (s *HTTPServer) handleGetMasterKeyConfig(c *fiber.Ctx) error {
	config := s.db.GetMasterKeyConfig()
	
	// Don't expose sensitive information in the response
	safeConfig := fiber.Map{
		"source": config.Source,
		"user_key_cache": fiber.Map{
			"enabled":       config.UserKeyCache.Enabled,
			"ttl":           config.UserKeyCache.TTL.String(),
			"max_idle_time": config.UserKeyCache.MaxIdleTime.String(),
		},
		"shamir_config": fiber.Map{
			"enabled":      config.ShamirConfig.Enabled,
			"threshold":    config.ShamirConfig.Threshold,
			"total_shares": config.ShamirConfig.TotalShares,
			"shares_path":  config.ShamirConfig.SharesPath,
		},
	}
	
	return c.JSON(safeConfig)
}

// handleSetMasterKeyConfig updates the master key configuration
func (s *HTTPServer) handleSetMasterKeyConfig(c *fiber.Ctx) error {
	var req struct {
		Source          velocity.MasterKeySource `json:"source"`
		UserKeyCache    velocity.UserKeyCacheConfig `json:"user_key_cache"`
		ShamirConfig    velocity.ShamirSecretConfig `json:"shamir_config"`
	}
	
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid JSON",
		})
	}
	
	// Validate source
	validSources := map[velocity.MasterKeySource]bool{
		velocity.SystemFile:   true,
		velocity.UserDefined:  true,
		velocity.ShamirShared: true,
	}
	
	if !validSources[req.Source] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid master key source",
		})
	}
	
	// Update configuration
	config := velocity.MasterKeyConfig{
		Source:       req.Source,
		UserKeyCache: req.UserKeyCache,
		ShamirConfig: req.ShamirConfig,
	}
	
	s.db.SetMasterKeyConfig(config)
	
	return c.JSON(fiber.Map{
		"status": "ok",
		"message": "Master key configuration updated",
	})
}

// handleRefreshMasterKey forces a refresh of the master key
func (s *HTTPServer) handleRefreshMasterKey(c *fiber.Ctx) error {
	err := s.db.RefreshMasterKey()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	
	return c.JSON(fiber.Map{
		"status": "ok",
		"message": "Master key refreshed successfully",
	})
}

// handleClearMasterKeyCache clears the cached master key
func (s *HTTPServer) handleClearMasterKeyCache(c *fiber.Ctx) error {
	s.db.ClearMasterKeyCache()
	
	return c.JSON(fiber.Map{
		"status": "ok",
		"message": "Master key cache cleared",
	})
}

// handleGetKeyCacheInfo returns information about the key cache
func (s *HTTPServer) handleGetKeyCacheInfo(c *fiber.Ctx) error {
	hasCachedKey, expiry, lastAccess := s.db.GetKeyCacheInfo()
	
	return c.JSON(fiber.Map{
		"has_cached_key": hasCachedKey,
		"cache_expiry":   expiry,
		"last_access":    lastAccess,
		"source":         s.db.GetMasterKeySource(),
	})
}
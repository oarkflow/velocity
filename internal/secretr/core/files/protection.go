// Package files provides self-protecting file functionality.
package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrProtectionViolation  = errors.New("protection: policy violation")
	ErrFileKilled           = errors.New("protection: file has been remotely killed")
	ErrUseCountExceeded     = errors.New("protection: use count exceeded")
	ErrLocationNotAllowed   = errors.New("protection: location not allowed")
	ErrDeviceNotAllowed     = errors.New("protection: device not allowed")
	ErrOfflineAccessExpired = errors.New("protection: offline access expired")
	ErrTimeWindowViolation  = errors.New("protection: outside allowed time window")
	ErrFileBurned           = errors.New("protection: file has been burned after read")
	ErrMFARequired          = errors.New("protection: multi-factor authentication required")
)

// FileProtectionPolicy defines protection rules for a file
type FileProtectionPolicy struct {
	ID     types.ID `json:"id"`
	FileID types.ID `json:"file_id"`
	Name   string   `json:"name"`

	// Use count limits
	MaxOpenCount         int `json:"max_open_count,omitempty"`
	MaxDownloadCount     int `json:"max_download_count,omitempty"`
	MaxPrintCount        int `json:"max_print_count,omitempty"`
	CurrentOpenCount     int `json:"current_open_count"`
	CurrentDownloadCount int `json:"current_download_count"`
	CurrentPrintCount    int `json:"current_print_count"`

	// Time-based restrictions
	ExpiresAt          *time.Time       `json:"expires_at,omitempty"`
	ValidFrom          *time.Time       `json:"valid_from,omitempty"`
	AllowedTimeWindows []TimeWindowRule `json:"allowed_time_windows,omitempty"`

	// Location/Device restrictions
	AllowedCountries   []string   `json:"allowed_countries,omitempty"`
	BlockedCountries   []string   `json:"blocked_countries,omitempty"`
	AllowedIPRanges    []string   `json:"allowed_ip_ranges,omitempty"`
	AllowedDeviceIDs   []types.ID `json:"allowed_device_ids,omitempty"`
	RequireDeviceTrust float64    `json:"require_device_trust,omitempty"`
	RequireMFA         bool       `json:"require_mfa,omitempty"`

	// Offline access
	AllowOffline       bool          `json:"allow_offline"`
	OfflineMaxDuration time.Duration `json:"offline_max_duration,omitempty"`
	OfflineExpiresAt   *time.Time    `json:"offline_expires_at,omitempty"`

	// Remote control
	RemoteKillEnabled bool       `json:"remote_kill_enabled"`
	IsKilled          bool       `json:"is_killed"`
	KilledAt          *time.Time `json:"killed_at,omitempty"`
	KilledBy          types.ID   `json:"killed_by,omitempty"`
	KillReason        string     `json:"kill_reason,omitempty"`

	// Watermarking
	WatermarkEnabled bool             `json:"watermark_enabled"`
	WatermarkType    WatermarkType    `json:"watermark_type,omitempty"`
	WatermarkData    *WatermarkConfig `json:"watermark_data,omitempty"`

	// Tracking
	TrackAccess   bool `json:"track_access"`
	TrackLocation bool `json:"track_location"`
	TrackDevice   bool `json:"track_device"`

	// Burn-after-read
	BurnAfterRead bool       `json:"burn_after_read"`
	IsBurned      bool       `json:"is_burned"`
	BurnedAt      *time.Time `json:"burned_at,omitempty"`
	BurnedBy      types.ID   `json:"burned_by,omitempty"`

	// Permissions
	AllowCopy       bool `json:"allow_copy"`
	AllowPrint      bool `json:"allow_print"`
	AllowScreenshot bool `json:"allow_screenshot"`
	AllowForward    bool `json:"allow_forward"`
	AllowEdit       bool `json:"allow_edit"`

	CreatedAt types.Timestamp    `json:"created_at"`
	UpdatedAt types.Timestamp    `json:"updated_at"`
	CreatedBy types.ID           `json:"created_by"`
	Status    types.EntityStatus `json:"status"`
}

// TimeWindowRule defines a time-based access window
type TimeWindowRule struct {
	Name      string `json:"name"`
	StartTime string `json:"start_time"` // HH:MM
	EndTime   string `json:"end_time"`   // HH:MM
	Days      []int  `json:"days"`       // 0=Sunday
	Timezone  string `json:"timezone"`
}

// WatermarkType represents the type of watermark
type WatermarkType string

const (
	WatermarkTypeText     WatermarkType = "text"
	WatermarkTypeImage    WatermarkType = "image"
	WatermarkTypeDynamic  WatermarkType = "dynamic"
	WatermarkTypeForensic WatermarkType = "forensic"
)

// WatermarkConfig holds watermark configuration
type WatermarkConfig struct {
	Text          string  `json:"text,omitempty"`
	IncludeUser   bool    `json:"include_user"`
	IncludeTime   bool    `json:"include_time"`
	IncludeIP     bool    `json:"include_ip"`
	IncludeDevice bool    `json:"include_device"`
	Opacity       float64 `json:"opacity"`
	Position      string  `json:"position"` // center, tiled, corner
	FontSize      int     `json:"font_size"`
	Color         string  `json:"color"` // hex color
}

// FileAccessLog represents a file access log entry
type FileAccessLog struct {
	ID            types.ID       `json:"id"`
	FileID        types.ID       `json:"file_id"`
	PolicyID      types.ID       `json:"policy_id"`
	AccessorID    types.ID       `json:"accessor_id"`
	DeviceID      types.ID       `json:"device_id,omitempty"`
	Action        string         `json:"action"` // open, download, print, copy
	Allowed       bool           `json:"allowed"`
	DenialReason  string         `json:"denial_reason,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
	IPAddress     string         `json:"ip_address,omitempty"`
	Country       string         `json:"country,omitempty"`
	DeviceInfo    types.Metadata `json:"device_info,omitempty"`
	WatermarkHash string         `json:"watermark_hash,omitempty"`
}

// FileDeleter is a callback function to delete a file from storage
type FileDeleter func(ctx context.Context, fileID types.ID) error

// ProtectionManager manages file protection policies
type ProtectionManager struct {
	mu          sync.RWMutex
	store       *storage.Store
	crypto      *crypto.Engine
	policyStore *storage.TypedStore[FileProtectionPolicy]
	logStore    *storage.TypedStore[FileAccessLog]
	policies    map[types.ID]*FileProtectionPolicy
	geoProvider GeoProvider
	fileDeleter FileDeleter
}

// GeoProvider provides geo-location lookup
type GeoProvider interface {
	LookupIP(ip string) (country string, err error)
}

// ProtectionManagerConfig configures the protection manager
type ProtectionManagerConfig struct {
	Store       *storage.Store
	GeoProvider GeoProvider
	FileDeleter FileDeleter
}

// NewProtectionManager creates a new protection manager
func NewProtectionManager(cfg ProtectionManagerConfig) *ProtectionManager {
	m := &ProtectionManager{
		store:       cfg.Store,
		crypto:      crypto.NewEngine(""),
		policyStore: storage.NewTypedStore[FileProtectionPolicy](cfg.Store, "file_protection"),
		logStore:    storage.NewTypedStore[FileAccessLog](cfg.Store, "file_access_logs"),
		policies:    make(map[types.ID]*FileProtectionPolicy),
		geoProvider: cfg.GeoProvider,
		fileDeleter: cfg.FileDeleter,
	}

	// Load existing policies
	ctx := context.Background()
	policies, _ := m.policyStore.List(ctx, "")
	for _, p := range policies {
		m.policies[p.FileID] = p
	}

	return m
}

// CreatePolicy creates a new protection policy
func (m *ProtectionManager) CreatePolicy(ctx context.Context, policy *FileProtectionPolicy) error {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	policy.ID = id
	policy.CreatedAt = types.Now()
	policy.UpdatedAt = types.Now()
	policy.Status = types.StatusActive

	if err := m.policyStore.Set(ctx, string(policy.ID), policy); err != nil {
		return err
	}

	m.mu.Lock()
	m.policies[policy.FileID] = policy
	m.mu.Unlock()

	return nil
}

// GetPolicy retrieves a policy for a file
func (m *ProtectionManager) GetPolicy(ctx context.Context, fileID types.ID) (*FileProtectionPolicy, error) {
	m.mu.RLock()
	if p, ok := m.policies[fileID]; ok {
		m.mu.RUnlock()
		return p, nil
	}
	m.mu.RUnlock()

	// Search in store
	policies, err := m.policyStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, p := range policies {
		if p.FileID == fileID {
			return p, nil
		}
	}

	return nil, errors.New("policy not found")
}

// UpdatePolicy updates a protection policy
func (m *ProtectionManager) UpdatePolicy(ctx context.Context, id types.ID, policy *FileProtectionPolicy) error {
	policy.ID = id
	policy.UpdatedAt = types.Now()

	if err := m.policyStore.Set(ctx, string(id), policy); err != nil {
		return err
	}

	m.mu.Lock()
	m.policies[policy.FileID] = policy
	m.mu.Unlock()

	return nil
}

// DeletePolicy deletes a protection policy
func (m *ProtectionManager) DeletePolicy(ctx context.Context, id types.ID) error {
	policy, _ := m.policyStore.Get(ctx, string(id))
	if policy != nil {
		m.mu.Lock()
		delete(m.policies, policy.FileID)
		m.mu.Unlock()
	}
	return m.policyStore.Delete(ctx, string(id))
}

// ValidateAccess validates access to a protected file
func (m *ProtectionManager) ValidateAccess(ctx context.Context, opts ValidateAccessOptions) (*AccessResult, error) {
	policy, err := m.GetPolicy(ctx, opts.FileID)
	if err != nil {
		// No policy means unrestricted access
		return &AccessResult{Allowed: true}, nil
	}

	result := &AccessResult{Allowed: false}

	// Check if file is killed
	if policy.IsKilled {
		result.Reason = "File has been remotely killed"
		_ = m.logAccess(ctx, policy, opts, false, ErrFileKilled.Error())
		return result, ErrFileKilled
	}

	// Check if file has been burned (burn-after-read)
	if policy.IsBurned {
		result.Reason = "File has been burned after initial read"
		_ = m.logAccess(ctx, policy, opts, false, ErrFileBurned.Error())
		return result, ErrFileBurned
	}

	// Check MFA requirement
	if policy.RequireMFA && !opts.MFAVerified {
		result.Reason = "Multi-factor authentication required"
		_ = m.logAccess(ctx, policy, opts, false, ErrMFARequired.Error())
		return result, ErrMFARequired
	}

	// Check time validity
	now := time.Now()
	if policy.ValidFrom != nil && now.Before(*policy.ValidFrom) {
		result.Reason = "Access not yet valid"
		_ = m.logAccess(ctx, policy, opts, false, result.Reason)
		return result, ErrProtectionViolation
	}

	if policy.ExpiresAt != nil && now.After(*policy.ExpiresAt) {
		result.Reason = "Access has expired"
		_ = m.logAccess(ctx, policy, opts, false, result.Reason)
		return result, ErrProtectionViolation
	}

	// Check use counts
	switch opts.Action {
	case "open":
		if policy.MaxOpenCount > 0 && policy.CurrentOpenCount >= policy.MaxOpenCount {
			result.Reason = "Maximum open count exceeded"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrUseCountExceeded
		}
	case "download":
		if policy.MaxDownloadCount > 0 && policy.CurrentDownloadCount >= policy.MaxDownloadCount {
			result.Reason = "Maximum download count exceeded"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrUseCountExceeded
		}
	case "print":
		if !policy.AllowPrint {
			result.Reason = "Printing not allowed"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrProtectionViolation
		}
		if policy.MaxPrintCount > 0 && policy.CurrentPrintCount >= policy.MaxPrintCount {
			result.Reason = "Maximum print count exceeded"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrUseCountExceeded
		}
	case "copy":
		if !policy.AllowCopy {
			result.Reason = "Copying not allowed"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrProtectionViolation
		}
	case "forward":
		if !policy.AllowForward {
			result.Reason = "Forwarding not allowed"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrProtectionViolation
		}
	}

	// Check device restrictions
	if len(policy.AllowedDeviceIDs) > 0 && opts.DeviceID != "" {
		found := false
		for _, allowedID := range policy.AllowedDeviceIDs {
			if allowedID == opts.DeviceID {
				found = true
				break
			}
		}
		if !found {
			result.Reason = "Device not allowed"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrDeviceNotAllowed
		}
	}

	// Check IP/location restrictions
	if opts.IPAddress != "" {
		if len(policy.AllowedIPRanges) > 0 {
			allowed := false
			for _, cidr := range policy.AllowedIPRanges {
				_, network, err := net.ParseCIDR(cidr)
				if err == nil && network.Contains(net.ParseIP(opts.IPAddress)) {
					allowed = true
					break
				}
			}
			if !allowed {
				result.Reason = "IP address not in allowed range"
				_ = m.logAccess(ctx, policy, opts, false, result.Reason)
				return result, ErrLocationNotAllowed
			}
		}

		// Check geo restrictions
		if m.geoProvider != nil && (len(policy.AllowedCountries) > 0 || len(policy.BlockedCountries) > 0) {
			country, _ := m.geoProvider.LookupIP(opts.IPAddress)

			if len(policy.BlockedCountries) > 0 {
				for _, blocked := range policy.BlockedCountries {
					if blocked == country {
						result.Reason = "Access from this country is blocked"
						_ = m.logAccess(ctx, policy, opts, false, result.Reason)
						return result, ErrLocationNotAllowed
					}
				}
			}

			if len(policy.AllowedCountries) > 0 {
				allowed := false
				for _, allowedCountry := range policy.AllowedCountries {
					if allowedCountry == country {
						allowed = true
						break
					}
				}
				if !allowed {
					result.Reason = "Access from this country is not allowed"
					_ = m.logAccess(ctx, policy, opts, false, result.Reason)
					return result, ErrLocationNotAllowed
				}
			}
		}
	}

	// Check time windows
	if len(policy.AllowedTimeWindows) > 0 {
		inWindow := false
		for _, tw := range policy.AllowedTimeWindows {
			if m.isInTimeWindow(now, tw) {
				inWindow = true
				break
			}
		}
		if !inWindow {
			result.Reason = "Access outside allowed time window"
			_ = m.logAccess(ctx, policy, opts, false, result.Reason)
			return result, ErrTimeWindowViolation
		}
	}

	// Update access counts
	switch opts.Action {
	case "open":
		policy.CurrentOpenCount++
	case "download":
		policy.CurrentDownloadCount++
	case "print":
		policy.CurrentPrintCount++
	}
	policy.UpdatedAt = types.Now()
	if err := m.policyStore.Set(ctx, string(policy.ID), policy); err != nil {
		// Ignore error? Or log properly? For now revert to ignore or just minimal handling.
		// Original code ignored it "_ = ...". Let's revert to "_ = " or just ignore body.
		// Reverting to original behavior for consistency with other parts if no logger available.
	}

	// Log successful access
	_ = m.logAccess(ctx, policy, opts, true, "")

	result.Allowed = true
	result.Policy = policy

	// Generate watermark if enabled
	if policy.WatermarkEnabled && policy.WatermarkData != nil {
		result.Watermark = m.generateWatermark(policy.WatermarkData, opts)
	}

	// Handle burn-after-read: mark file as burned and optionally delete
	if policy.BurnAfterRead && !policy.IsBurned {
		burnTime := time.Now()
		policy.IsBurned = true
		policy.BurnedAt = &burnTime
		policy.BurnedBy = opts.AccessorID
		policy.UpdatedAt = types.Now()

		// Update the policy in storage
		if err := m.policyStore.Set(ctx, string(policy.ID), policy); err == nil {
			m.mu.Lock()
			m.policies[opts.FileID] = policy
			m.mu.Unlock()
		}

		result.Burned = true

		// Optionally delete the actual file data (async to not block response)
		if m.fileDeleter != nil {
			go func() {
				bgCtx := context.Background()
				_ = m.fileDeleter(bgCtx, opts.FileID)
			}()
		}

		result.Burned = true
	}

	return result, nil
}

// ValidateAccessOptions holds options for access validation
type ValidateAccessOptions struct {
	FileID      types.ID
	AccessorID  types.ID
	DeviceID    types.ID
	Action      string
	IPAddress   string
	IsOffline   bool
	MFAVerified bool
}

// AccessResult represents the result of access validation
type AccessResult struct {
	Allowed   bool                  `json:"allowed"`
	Reason    string                `json:"reason,omitempty"`
	Policy    *FileProtectionPolicy `json:"policy,omitempty"`
	Watermark *GeneratedWatermark   `json:"watermark,omitempty"`
	Burned    bool                  `json:"burned,omitempty"` // True if file was burned after this access
}

// GeneratedWatermark represents a generated watermark
type GeneratedWatermark struct {
	Text      string `json:"text"`
	Hash      string `json:"hash"`
	ImageData []byte `json:"image_data,omitempty"`
}

// isInTimeWindow checks if current time is within a time window
func (m *ProtectionManager) isInTimeWindow(t time.Time, tw TimeWindowRule) bool {
	loc, err := time.LoadLocation(tw.Timezone)
	if err != nil {
		loc = time.UTC
	}

	localTime := t.In(loc)
	weekday := int(localTime.Weekday())

	// Check day
	dayAllowed := false
	for _, d := range tw.Days {
		if d == weekday {
			dayAllowed = true
			break
		}
	}
	if !dayAllowed {
		return false
	}

	// Parse times
	currentMinutes := localTime.Hour()*60 + localTime.Minute()
	startMinutes := m.parseTimeMinutes(tw.StartTime)
	endMinutes := m.parseTimeMinutes(tw.EndTime)

	return currentMinutes >= startMinutes && currentMinutes <= endMinutes
}

func (m *ProtectionManager) parseTimeMinutes(timeStr string) int {
	t, err := time.Parse("15:04", timeStr)
	if err != nil {
		return 0
	}
	return t.Hour()*60 + t.Minute()
}

// generateWatermark generates a watermark
func (m *ProtectionManager) generateWatermark(config *WatermarkConfig, opts ValidateAccessOptions) *GeneratedWatermark {
	text := config.Text

	if config.IncludeUser {
		text += " | User: " + string(opts.AccessorID)
	}
	if config.IncludeTime {
		text += " | " + time.Now().Format(time.RFC3339)
	}
	if config.IncludeIP {
		text += " | IP: " + opts.IPAddress
	}
	if config.IncludeDevice && opts.DeviceID != "" {
		text += " | Device: " + string(opts.DeviceID)
	}

	hash := sha256.Sum256([]byte(text))

	wm := &GeneratedWatermark{
		Text: text,
		Hash: hex.EncodeToString(hash[:]),
	}

	// Generate image watermark if needed
	if config.Position == "tiled" || config.Position == "center" {
		wm.ImageData = m.generateWatermarkImage(text, config)
	}

	return wm
}

// generateWatermarkImage generates a simple watermark image
func (m *ProtectionManager) generateWatermarkImage(text string, config *WatermarkConfig) []byte {
	// Create a simple transparent image with text
	width, height := 400, 100
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Fill with transparent background
	draw.Draw(img, img.Bounds(), &image.Uniform{color.Transparent}, image.Point{}, draw.Src)

	// For now, just create a placeholder - in production, you'd use a font rendering library
	// This is simplified for demonstration
	textColor := color.RGBA{128, 128, 128, uint8(255 * config.Opacity)}
	for x := 0; x < width; x++ {
		for y := height/2 - 1; y <= height/2+1; y++ {
			if y >= 0 && y < height {
				img.Set(x, y, textColor)
			}
		}
	}

	// Encode to PNG
	var buf []byte
	w := &bytesWriter{data: buf}
	_ = png.Encode(w, img)
	return w.data
}

type bytesWriter struct {
	data []byte
}

func (w *bytesWriter) Write(p []byte) (n int, err error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

// logAccess logs a file access attempt
func (m *ProtectionManager) logAccess(ctx context.Context, policy *FileProtectionPolicy, opts ValidateAccessOptions, allowed bool, reason string) error {
	if policy != nil && !policy.TrackAccess {
		return nil
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	log := &FileAccessLog{
		ID:           id,
		FileID:       opts.FileID,
		AccessorID:   opts.AccessorID,
		DeviceID:     opts.DeviceID,
		Action:       opts.Action,
		Allowed:      allowed,
		DenialReason: reason,
		Timestamp:    time.Now(),
		IPAddress:    opts.IPAddress,
	}

	if policy != nil {
		log.PolicyID = policy.ID
	}

	// Lookup Country
	if m.geoProvider != nil && log.IPAddress != "" {
		if country, err := m.geoProvider.LookupIP(log.IPAddress); err == nil {
			log.Country = country
		}
	}

	return m.logStore.Set(ctx, string(log.ID), log)
}

// KillFile remotely kills a file
func (m *ProtectionManager) KillFile(ctx context.Context, fileID types.ID, killedBy types.ID, reason string) error {
	policy, err := m.GetPolicy(ctx, fileID)
	if err != nil {
		return err
	}

	if !policy.RemoteKillEnabled {
		return errors.New("remote kill not enabled for this file")
	}

	now := time.Now()
	policy.IsKilled = true
	policy.KilledAt = &now
	policy.KilledBy = killedBy
	policy.KillReason = reason
	policy.UpdatedAt = types.Now()

	if err := m.policyStore.Set(ctx, string(policy.ID), policy); err != nil {
		return err
	}

	m.mu.Lock()
	m.policies[fileID] = policy
	m.mu.Unlock()

	return nil
}

// ReviveFile revives a killed file
func (m *ProtectionManager) ReviveFile(ctx context.Context, fileID types.ID) error {
	policy, err := m.GetPolicy(ctx, fileID)
	if err != nil {
		return err
	}

	policy.IsKilled = false
	policy.KilledAt = nil
	policy.KilledBy = ""
	policy.KillReason = ""
	policy.UpdatedAt = types.Now()

	if err := m.policyStore.Set(ctx, string(policy.ID), policy); err != nil {
		return err
	}

	m.mu.Lock()
	m.policies[fileID] = policy
	m.mu.Unlock()

	return nil
}

// ListAccessLogs retrieves access logs for a file (optional) with limit
func (m *ProtectionManager) ListAccessLogs(ctx context.Context, fileID types.ID, limit int) ([]*FileAccessLog, error) {
	all, err := m.logStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var logs []*FileAccessLog
	for _, log := range all {
		if fileID != "" && log.FileID != fileID {
			continue
		}
		logs = append(logs, log)
		if limit > 0 && len(logs) >= limit {
			break
		}
	}

	return logs, nil
}

// ExportFileReport exports a protection report for a file
func (m *ProtectionManager) ExportFileReport(ctx context.Context, fileID types.ID) ([]byte, error) {
	policy, err := m.GetPolicy(ctx, fileID)
	if err != nil {
		return nil, err
	}

	logs, _ := m.ListAccessLogs(ctx, fileID, 0)

	report := map[string]any{
		"file_id":      fileID,
		"policy":       policy,
		"access_logs":  logs,
		"generated_at": time.Now(),
	}

	return json.MarshalIndent(report, "", "  ")
}

// Close cleans up resources
func (m *ProtectionManager) Close() error {
	return m.crypto.Close()
}

// Ensure io.Writer interface is implemented
var _ io.Writer = (*bytesWriter)(nil)

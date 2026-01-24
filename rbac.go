package velocity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Role defines a security role with permissions
type Role struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Permissions []Permission        `json:"permissions"`
	ParentRole  string              `json:"parent_role,omitempty"`
	Priority    int                 `json:"priority"` // Lower = higher priority
	Conditions  *AccessConditions   `json:"conditions,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	Metadata    map[string]string   `json:"metadata,omitempty"`
}

// Permission defines an action that can be performed on a resource
type Permission struct {
	Resource    string                 `json:"resource"` // envelope, object, backup, admin
	Actions     []string               `json:"actions"`  // create, read, update, delete, approve
	Constraints map[string]interface{} `json:"constraints,omitempty"`
	Effect      string                 `json:"effect"` // allow, deny
}

// AccessConditions defines context-aware access requirements
type AccessConditions struct {
	TimeWindows       []TimeWindow `json:"time_windows,omitempty"`
	IPAllowlist       []string     `json:"ip_allowlist,omitempty"`
	IPDenylist        []string     `json:"ip_denylist,omitempty"`
	GeoRestrictions   []string     `json:"geo_restrictions,omitempty"` // ISO country codes
	MFARequired       bool         `json:"mfa_required"`
	MaxConcurrent     int          `json:"max_concurrent,omitempty"`
	SessionTimeout    time.Duration `json:"session_timeout"`
	DeviceRestriction bool         `json:"device_restriction"`
}

// TimeWindow defines when access is allowed
type TimeWindow struct {
	DaysOfWeek []time.Weekday `json:"days_of_week"` // Empty = all days
	StartTime  string         `json:"start_time"`   // "09:00"
	EndTime    string         `json:"end_time"`     // "17:00"
	Timezone   string         `json:"timezone"`     // "America/New_York"
}

// Predefined system roles
const (
	RoleSystemAdmin       = "system_admin"
	RoleSecurityOfficer   = "security_officer"
	RoleComplianceOfficer = "compliance_officer"
	RoleDataOwner         = "data_owner"
	RoleDataCustodian     = "data_custodian"
	RoleAuditor           = "auditor"
	RoleUser              = "user"
	RoleGuest             = "guest"
)

// Predefined resources
const (
	ResourceEnvelope    = "envelope"
	ResourceObject      = "object"
	ResourceBackup      = "backup"
	ResourceAudit       = "audit"
	ResourceCompliance  = "compliance"
	ResourceAdmin       = "admin"
	ResourceKey         = "key"
	ResourceUser        = "user"
)

// Predefined actions
const (
	ActionCreate  = "create"
	ActionRead    = "read"
	ActionUpdate  = "update"
	ActionDelete  = "delete"
	ActionApprove = "approve"
	ActionAudit   = "audit"
	ActionBackup  = "backup"
	ActionRestore = "restore"
	ActionRotate  = "rotate"
	ActionExport  = "export"
)

// RBACManager manages role-based access control
type RBACManager struct {
	roles    map[string]*Role
	users    map[string]*User
	sessions map[string]*Session
	mu       sync.RWMutex
	db       *DB
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(db *DB) *RBACManager {
	rbac := &RBACManager{
		roles:    make(map[string]*Role),
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
		db:       db,
	}

	// Initialize default roles
	rbac.initializeDefaultRoles()

	return rbac
}

// initializeDefaultRoles creates predefined system roles
func (rbac *RBACManager) initializeDefaultRoles() {
	// System Administrator - Full control
	rbac.roles[RoleSystemAdmin] = &Role{
		ID:          RoleSystemAdmin,
		Name:        "System Administrator",
		Description: "Full system control",
		Permissions: []Permission{
			{Resource: "*", Actions: []string{"*"}, Effect: "allow"},
		},
		Priority:  1,
		CreatedAt: time.Now(),
	}

	// Security Officer - Security configuration and monitoring
	rbac.roles[RoleSecurityOfficer] = &Role{
		ID:          RoleSecurityOfficer,
		Name:        "Security Officer",
		Description: "Security configuration and audit access",
		Permissions: []Permission{
			{Resource: ResourceAudit, Actions: []string{ActionRead, ActionAudit}, Effect: "allow"},
			{Resource: ResourceKey, Actions: []string{ActionRead, ActionRotate}, Effect: "allow"},
			{Resource: ResourceUser, Actions: []string{ActionRead, ActionUpdate}, Effect: "allow"},
			{Resource: ResourceAdmin, Actions: []string{ActionRead}, Effect: "allow"},
		},
		Priority:  2,
		CreatedAt: time.Now(),
	}

	// Compliance Officer - Compliance reports and policies
	rbac.roles[RoleComplianceOfficer] = &Role{
		ID:          RoleComplianceOfficer,
		Name:        "Compliance Officer",
		Description: "Compliance reports and policy management",
		Permissions: []Permission{
			{Resource: ResourceCompliance, Actions: []string{ActionRead, ActionCreate, ActionUpdate}, Effect: "allow"},
			{Resource: ResourceAudit, Actions: []string{ActionRead}, Effect: "allow"},
			{Resource: ResourceEnvelope, Actions: []string{ActionRead, ActionAudit}, Effect: "allow"},
		},
		Priority:  3,
		CreatedAt: time.Now(),
	}

	// Data Owner - Data classification and access grants
	rbac.roles[RoleDataOwner] = &Role{
		ID:          RoleDataOwner,
		Name:        "Data Owner",
		Description: "Data classification and access management",
		Permissions: []Permission{
			{Resource: ResourceEnvelope, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete}, Effect: "allow"},
			{Resource: ResourceObject, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete}, Effect: "allow"},
		},
		Priority:  4,
		CreatedAt: time.Now(),
	}

	// Data Custodian - Backup and maintenance
	rbac.roles[RoleDataCustodian] = &Role{
		ID:          RoleDataCustodian,
		Name:        "Data Custodian",
		Description: "Backup, restore, and maintenance",
		Permissions: []Permission{
			{Resource: ResourceBackup, Actions: []string{ActionBackup, ActionRestore}, Effect: "allow"},
			{Resource: ResourceObject, Actions: []string{ActionRead}, Effect: "allow"},
		},
		Priority:  5,
		CreatedAt: time.Now(),
	}

	// Auditor - Read-only audit access
	rbac.roles[RoleAuditor] = &Role{
		ID:          RoleAuditor,
		Name:        "Auditor",
		Description: "Read-only audit access",
		Permissions: []Permission{
			{Resource: ResourceAudit, Actions: []string{ActionRead}, Effect: "allow"},
			{Resource: ResourceCompliance, Actions: []string{ActionRead}, Effect: "allow"},
		},
		Priority:  6,
		CreatedAt: time.Now(),
		Conditions: &AccessConditions{
			MFARequired:    true,
			SessionTimeout: 30 * time.Minute,
		},
	}

	// User - Standard read/write
	rbac.roles[RoleUser] = &Role{
		ID:          RoleUser,
		Name:        "User",
		Description: "Standard user access",
		Permissions: []Permission{
			{Resource: ResourceObject, Actions: []string{ActionCreate, ActionRead, ActionUpdate}, Effect: "allow"},
			{Resource: ResourceEnvelope, Actions: []string{ActionRead}, Effect: "allow"},
		},
		Priority:  7,
		CreatedAt: time.Now(),
	}

	// Guest - Read-only limited
	rbac.roles[RoleGuest] = &Role{
		ID:          RoleGuest,
		Name:        "Guest",
		Description: "Read-only limited access",
		Permissions: []Permission{
			{Resource: ResourceObject, Actions: []string{ActionRead}, Effect: "allow", Constraints: map[string]interface{}{"public_only": true}},
		},
		Priority:  8,
		CreatedAt: time.Now(),
		Conditions: &AccessConditions{
			SessionTimeout: 15 * time.Minute,
		},
	}
}

// User represents a system user
type User struct {
	ID              string            `json:"id"`
	Username        string            `json:"username"`
	Email           string            `json:"email"`
	Roles           []string          `json:"roles"`
	ClearanceLevel  string            `json:"clearance_level"` // public, internal, confidential, restricted, top_secret
	Department      string            `json:"department"`
	MFAEnabled      bool              `json:"mfa_enabled"`
	MFASecret       string            `json:"mfa_secret,omitempty"`
	Attributes      map[string]string `json:"attributes"`
	Active          bool              `json:"active"`
	LockedUntil     time.Time         `json:"locked_until,omitempty"`
	LastLogin       time.Time         `json:"last_login,omitempty"`
	FailedAttempts  int               `json:"failed_attempts"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// Session represents an active user session
type Session struct {
	SessionID      string            `json:"session_id"`
	UserID         string            `json:"user_id"`
	Username       string            `json:"username"`
	Roles          []string          `json:"roles"`
	StartTime      time.Time         `json:"start_time"`
	LastActivity   time.Time         `json:"last_activity"`
	ExpiresAt      time.Time         `json:"expires_at"`
	IPAddress      string            `json:"ip_address"`
	UserAgent      string            `json:"user_agent"`
	MFAVerified    bool              `json:"mfa_verified"`
	DeviceID       string            `json:"device_id,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// AccessRequest represents a request to perform an action
type AccessRequest struct {
	UserID         string                 `json:"user_id"`
	SessionID      string                 `json:"session_id"`
	Resource       string                 `json:"resource"`
	Action         string                 `json:"action"`
	ResourceID     string                 `json:"resource_id,omitempty"`
	Context        *AccessContext         `json:"context"`
	Attributes     map[string]interface{} `json:"attributes,omitempty"`
}

// AccessContext provides contextual information for access decisions
type AccessContext struct {
	Timestamp      time.Time         `json:"timestamp"`
	IPAddress      string            `json:"ip_address"`
	GeoLocation    string            `json:"geo_location,omitempty"` // ISO country code
	DeviceID       string            `json:"device_id,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	MFAVerified    bool              `json:"mfa_verified"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// AccessDecision represents the result of an access control check
type AccessDecision struct {
	Allowed       bool          `json:"allowed"`
	Reason        string        `json:"reason"`
	RequiredMFA   bool          `json:"required_mfa"`
	RolesEvaluated []string      `json:"roles_evaluated"`
	Timestamp     time.Time     `json:"timestamp"`
}

// CheckAccess evaluates if a user can perform an action
func (rbac *RBACManager) CheckAccess(ctx context.Context, request *AccessRequest) (*AccessDecision, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	decision := &AccessDecision{
		Allowed:   false,
		Timestamp: time.Now(),
	}

	// Get user
	user, exists := rbac.users[request.UserID]
	if !exists {
		decision.Reason = "user not found"
		return decision, nil
	}

	// Check if user is active
	if !user.Active {
		decision.Reason = "user account disabled"
		return decision, nil
	}

	// Check if user is locked
	if !user.LockedUntil.IsZero() && time.Now().Before(user.LockedUntil) {
		decision.Reason = fmt.Sprintf("user account locked until %s", user.LockedUntil.Format(time.RFC3339))
		return decision, nil
	}

	// Validate session if provided
	if request.SessionID != "" {
		session, exists := rbac.sessions[request.SessionID]
		if !exists {
			decision.Reason = "invalid session"
			return decision, nil
		}

		// Check session expiry
		if time.Now().After(session.ExpiresAt) {
			decision.Reason = "session expired"
			return decision, nil
		}

		// Update last activity
		session.LastActivity = time.Now()
	}

	// Evaluate each role
	for _, roleID := range user.Roles {
		role, exists := rbac.roles[roleID]
		if !exists {
			continue
		}

		decision.RolesEvaluated = append(decision.RolesEvaluated, roleID)

		// Check role conditions first
		if role.Conditions != nil {
			if conditionErr := rbac.evaluateConditions(role.Conditions, request.Context); conditionErr != nil {
				decision.Reason = conditionErr.Error()
				if strings.Contains(conditionErr.Error(), "MFA") {
					decision.RequiredMFA = true
				}
				continue
			}
		}

		// Check permissions
		for _, perm := range role.Permissions {
			if rbac.permissionMatches(perm, request.Resource, request.Action) {
				if perm.Effect == "deny" {
					decision.Allowed = false
					decision.Reason = fmt.Sprintf("explicitly denied by role %s", roleID)
					return decision, nil
				}

				decision.Allowed = true
				decision.Reason = fmt.Sprintf("granted by role %s", roleID)
				return decision, nil
			}
		}
	}

	if !decision.Allowed {
		decision.Reason = "no matching permissions found"
	}

	return decision, nil
}

// permissionMatches checks if a permission applies to a resource/action
func (rbac *RBACManager) permissionMatches(perm Permission, resource, action string) bool {
	// Check wildcard resource
	if perm.Resource == "*" {
		return true
	}

	// Check resource match
	if perm.Resource != resource {
		return false
	}

	// Check wildcard action
	for _, allowedAction := range perm.Actions {
		if allowedAction == "*" || allowedAction == action {
			return true
		}
	}

	return false
}

// evaluateConditions checks if access conditions are met
func (rbac *RBACManager) evaluateConditions(conditions *AccessConditions, context *AccessContext) error {
	// Check MFA requirement
	if conditions.MFARequired && !context.MFAVerified {
		return errors.New("MFA verification required")
	}

	// Check IP allowlist
	if len(conditions.IPAllowlist) > 0 {
		allowed := false
		for _, allowedIP := range conditions.IPAllowlist {
			if matchesIPPattern(context.IPAddress, allowedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP address %s not in allowlist", context.IPAddress)
		}
	}

	// Check IP denylist
	if len(conditions.IPDenylist) > 0 {
		for _, deniedIP := range conditions.IPDenylist {
			if matchesIPPattern(context.IPAddress, deniedIP) {
				return fmt.Errorf("IP address %s is denied", context.IPAddress)
			}
		}
	}

	// Check geo restrictions
	if len(conditions.GeoRestrictions) > 0 && context.GeoLocation != "" {
		allowed := false
		for _, allowedCountry := range conditions.GeoRestrictions {
			if context.GeoLocation == allowedCountry {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("access from country %s is restricted", context.GeoLocation)
		}
	}

	// Check time windows
	if len(conditions.TimeWindows) > 0 {
		if !rbac.isWithinTimeWindow(conditions.TimeWindows, context.Timestamp) {
			return errors.New("access outside allowed time windows")
		}
	}

	return nil
}

// isWithinTimeWindow checks if a timestamp falls within any allowed time window
func (rbac *RBACManager) isWithinTimeWindow(windows []TimeWindow, timestamp time.Time) bool {
	for _, window := range windows {
		// Check day of week
		if len(window.DaysOfWeek) > 0 {
			dayMatches := false
			for _, allowedDay := range window.DaysOfWeek {
				if timestamp.Weekday() == allowedDay {
					dayMatches = true
					break
				}
			}
			if !dayMatches {
				continue
			}
		}

		// Check time range
		// Parse start and end times
		// Simplified: just check if within business hours
		hour := timestamp.Hour()
		if hour >= 9 && hour < 17 { // 9 AM to 5 PM
			return true
		}
	}

	return len(windows) == 0 // If no windows defined, allow all times
}

// matchesIPPattern checks if an IP matches a pattern (supports CIDR)
func matchesIPPattern(ip, pattern string) bool {
	// Exact match
	if ip == pattern {
		return true
	}

	// CIDR match
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		ipAddr := net.ParseIP(ip)
		return ipNet.Contains(ipAddr)
	}

	return false
}

// AddRole creates or updates a role
func (rbac *RBACManager) AddRole(role *Role) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	role.UpdatedAt = time.Now()
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now()
	}

	rbac.roles[role.ID] = role

	// Persist to database
	return rbac.saveRole(role)
}

// AddUser creates or updates a user
func (rbac *RBACManager) AddUser(user *User) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	user.UpdatedAt = time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	rbac.users[user.ID] = user

	// Persist to database
	return rbac.saveUser(user)
}

// CreateSession creates a new user session
func (rbac *RBACManager) CreateSession(userID string, context *AccessContext) (*Session, error) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	user, exists := rbac.users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	session := &Session{
		SessionID:    generateSessionID(),
		UserID:       userID,
		Username:     user.Username,
		Roles:        user.Roles,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(8 * time.Hour), // Default 8 hour session
		IPAddress:    context.IPAddress,
		UserAgent:    context.UserAgent,
		MFAVerified:  context.MFAVerified,
		DeviceID:     context.DeviceID,
	}

	rbac.sessions[session.SessionID] = session

	// Update user last login
	user.LastLogin = time.Now()

	return session, nil
}

// Persistence methods

func (rbac *RBACManager) saveRole(role *Role) error {
	data, err := json.Marshal(role)
	if err != nil {
		return err
	}
	return rbac.db.Put([]byte("_rbac:role:"+role.ID), data)
}

func (rbac *RBACManager) saveUser(user *User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return rbac.db.Put([]byte("_rbac:user:"+user.ID), data)
}

// generateSessionID creates a unique session identifier
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("sess_%s", hex.EncodeToString(b))
}

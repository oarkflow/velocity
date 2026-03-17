// Package types contains core type definitions for the Secretr platform.
package types

import (
	"encoding/json"
	"time"
)

// ID represents a unique identifier
type ID string

// Timestamp represents a point in time with nanosecond precision
type Timestamp int64

// Now returns the current timestamp
func Now() Timestamp {
	return Timestamp(time.Now().UnixNano())
}

// Time converts timestamp to time.Time
func (t Timestamp) Time() time.Time {
	return time.Unix(0, int64(t))
}

// Scope represents a permission scope for feature gating
type Scope string

// Core permission scopes
const (
	// Authentication scopes
	ScopeAuthLogin  Scope = "auth:login"
	ScopeAuthLogout Scope = "auth:logout"
	ScopeAuthRotate Scope = "auth:rotate"

	// Identity scopes
	ScopeIdentityCreate     Scope = "identity:create"
	ScopeIdentityRead       Scope = "identity:read"
	ScopeIdentityUpdate     Scope = "identity:update"
	ScopeIdentityDelete     Scope = "identity:delete"
	ScopeIdentityRecover    Scope = "identity:recover"
	ScopeIdentityManage     Scope = "identity:manage"
	ScopeIdentityService    Scope = "identity:service"
	ScopeIdentityProvenance Scope = "identity:provenance"

	// Device scopes
	ScopeDeviceEnroll      Scope = "device:enroll"
	ScopeDeviceRead        Scope = "device:read"
	ScopeDeviceRevoke      Scope = "device:revoke"
	ScopeDeviceAttest      Scope = "device:attest"
	ScopeDeviceTrust       Scope = "device:trust"
	ScopeDeviceFingerprint Scope = "device:fingerprint"

	// Session scopes
	ScopeSessionCreate  Scope = "session:create"
	ScopeSessionRead    Scope = "session:read"
	ScopeSessionRevoke  Scope = "session:revoke"
	ScopeSessionOffline Scope = "session:offline"

	// Key management scopes
	ScopeKeyGenerate Scope = "key:generate"
	ScopeKeyRead     Scope = "key:read"
	ScopeKeyRotate   Scope = "key:rotate"
	ScopeKeyDestroy  Scope = "key:destroy"
	ScopeKeyExport   Scope = "key:export"
	ScopeKeyImport   Scope = "key:import"
	ScopeKeyVersion  Scope = "key:version"
	ScopeKeyRecovery Scope = "key:recovery"
	ScopeKeyEscrow   Scope = "key:escrow"
	ScopeKeyHardware Scope = "key:hardware"

	// Secret scopes
	ScopeSecretCreate  Scope = "secret:create"
	ScopeSecretRead    Scope = "secret:read"
	ScopeSecretUpdate  Scope = "secret:update"
	ScopeSecretDelete  Scope = "secret:delete"
	ScopeSecretList    Scope = "secret:list"
	ScopeSecretHistory Scope = "secret:history"
	ScopeSecretRotate  Scope = "secret:rotate"
	ScopeSecretShare   Scope = "secret:share"
	ScopeSecretExport  Scope = "secret:export"

	// File scopes
	ScopeFileUpload   Scope = "file:upload"
	ScopeFileDownload Scope = "file:download"
	ScopeFileList     Scope = "file:list"
	ScopeFileDelete   Scope = "file:delete"
	ScopeFileSeal     Scope = "file:seal"
	ScopeFileUnseal   Scope = "file:unseal"
	ScopeFileShred    Scope = "file:shred"
	ScopeFileShare    Scope = "file:share"
	ScopeFileExport   Scope = "file:export"

	// Access control scopes
	ScopeAccessGrant     Scope = "access:grant"
	ScopeAccessRevoke    Scope = "access:revoke"
	ScopeAccessDelegate  Scope = "access:delegate"
	ScopeAccessRead      Scope = "access:read"
	ScopeAccessApprove   Scope = "access:approve"
	ScopeAccessEmergency Scope = "access:emergency"
	ScopeAccessInherit   Scope = "access:inherit"

	// Role scopes
	ScopeRoleCreate Scope = "role:create"
	ScopeRoleRead   Scope = "role:read"
	ScopeRoleUpdate Scope = "role:update"
	ScopeRoleDelete Scope = "role:delete"
	ScopeRoleAssign Scope = "role:assign"

	// Policy scopes
	ScopePolicyCreate   Scope = "policy:create"
	ScopePolicyRead     Scope = "policy:read"
	ScopePolicyUpdate   Scope = "policy:update"
	ScopePolicyDelete   Scope = "policy:delete"
	ScopePolicyBind     Scope = "policy:bind"
	ScopePolicySimulate Scope = "policy:simulate"
	ScopePolicyFreeze   Scope = "policy:freeze"
	ScopePolicySign     Scope = "policy:sign"

	// Audit scopes
	ScopeAuditRead   Scope = "audit:read"
	ScopeAuditQuery  Scope = "audit:query"
	ScopeAuditExport Scope = "audit:export"
	ScopeAuditVerify Scope = "audit:verify"
	ScopeAuditRedact Scope = "audit:redact"

	// Share scopes
	ScopeShareCreate   Scope = "share:create"
	ScopeShareRead     Scope = "share:read"
	ScopeShareRevoke   Scope = "share:revoke"
	ScopeShareAccept   Scope = "share:accept"
	ScopeShareExport   Scope = "share:export"
	ScopeShareReshare  Scope = "share:reshare"
	ScopeShareExternal Scope = "share:external"

	// Backup scopes
	ScopeBackupCreate   Scope = "backup:create"
	ScopeBackupRestore  Scope = "backup:restore"
	ScopeBackupVerify   Scope = "backup:verify"
	ScopeBackupSchedule Scope = "backup:schedule"
	ScopeBackupQuorum   Scope = "backup:quorum"

	// Organization scopes
	ScopeOrgCreate     Scope = "org:create"
	ScopeOrgRead       Scope = "org:read"
	ScopeOrgUpdate     Scope = "org:update"
	ScopeOrgDelete     Scope = "org:delete"
	ScopeOrgInvite     Scope = "org:invite"
	ScopeOrgRevoke     Scope = "org:revoke"
	ScopeOrgTeams      Scope = "org:teams"
	ScopeOrgEnv        Scope = "org:environments"
	ScopeOrgCompliance Scope = "org:compliance"
	ScopeOrgAuditor    Scope = "org:auditor"
	ScopeOrgOnboard    Scope = "org:onboard"
	ScopeOrgOffboard   Scope = "org:offboard"
	ScopeOrgLegalHold  Scope = "org:legal_hold"

	// Incident scopes
	ScopeIncidentDeclare  Scope = "incident:declare"
	ScopeIncidentFreeze   Scope = "incident:freeze"
	ScopeIncidentRotate   Scope = "incident:rotate"
	ScopeIncidentExport   Scope = "incident:export"
	ScopeIncidentMonitor  Scope = "incident:monitor"
	ScopeIncidentTimeline Scope = "incident:timeline"

	// Envelope Scopes
	ScopeEnvelopeCreate Scope = "envelope:create"
	ScopeEnvelopeOpen   Scope = "envelope:open"
	ScopeEnvelopeVerify Scope = "envelope:verify"

	// External Auditor scopes
	ScopeAuditorRead   Scope = "auditor:read"
	ScopeAuditorExport Scope = "auditor:export"

	// Vendor scopes
	ScopeVendorAccess  Scope = "vendor:access"
	ScopeVendorLimited Scope = "vendor:limited"
	ScopeVendorManage  Scope = "vendor:manage"

	// SSH scopes
	ScopeSSHProfile Scope = "ssh:profile"
	ScopeSSHConnect Scope = "ssh:connect"
	ScopeSSHExecute Scope = "ssh:execute"
	ScopeSSHManage  Scope = "ssh:manage"

	// CI/CD scopes
	ScopePipelineCreate  Scope = "pipeline:create"
	ScopePipelineAuth    Scope = "pipeline:auth"
	ScopePipelineInject  Scope = "pipeline:inject"
	ScopePipelineEnforce Scope = "pipeline:enforce"

	// Exec scopes
	ScopeExecRun Scope = "exec:run"

	// Transfer scopes (M&A)
	ScopeTransferInit    Scope = "transfer:init"
	ScopeTransferApprove Scope = "transfer:approve"
	ScopeTransferExecute Scope = "transfer:execute"

	// Admin scopes
	ScopeAdminAll      Scope = "admin:*"
	ScopeAdminUsers    Scope = "admin:users"
	ScopeAdminSystem   Scope = "admin:system"
	ScopeAdminSecurity Scope = "admin:security"

	// Advanced enterprise scopes
	ScopeComplianceReport Scope = "compliance:report"
	ScopeCompliancePolicy Scope = "compliance:policy"
	ScopeDLPScan          Scope = "dlp:scan"
	ScopeDLPRules         Scope = "dlp:rules"
	ScopeAccessRequest    Scope = "access:request"
	ScopeAutomationManage Scope = "automation:manage"
)

// ScopeSet represents a set of scopes
type ScopeSet map[Scope]struct{}

// NewScopeSet creates a new scope set from scopes
func NewScopeSet(scopes ...Scope) ScopeSet {
	ss := make(ScopeSet, len(scopes))
	for _, s := range scopes {
		ss[s] = struct{}{}
	}
	return ss
}

// Has checks if the scope set contains the given scope
func (ss ScopeSet) Has(scope Scope) bool {
	if _, ok := ss[ScopeAdminAll]; ok {
		return true // Admin has all scopes
	}
	_, ok := ss[scope]
	return ok
}

// HasAny checks if the scope set contains any of the given scopes
func (ss ScopeSet) HasAny(scopes ...Scope) bool {
	for _, s := range scopes {
		if ss.Has(s) {
			return true
		}
	}
	return false
}

// HasAll checks if the scope set contains all of the given scopes
func (ss ScopeSet) HasAll(scopes ...Scope) bool {
	for _, s := range scopes {
		if !ss.Has(s) {
			return false
		}
	}
	return true
}

// Add adds scopes to the set
func (ss ScopeSet) Add(scopes ...Scope) {
	for _, s := range scopes {
		ss[s] = struct{}{}
	}
}

// Remove removes scopes from the set
func (ss ScopeSet) Remove(scopes ...Scope) {
	for _, s := range scopes {
		delete(ss, s)
	}
}

// Scopes returns all scopes as a slice
func (ss ScopeSet) Scopes() []Scope {
	scopes := make([]Scope, 0, len(ss))
	for s := range ss {
		scopes = append(scopes, s)
	}
	return scopes
}

// IdentityType represents the type of identity
type IdentityType string

const (
	IdentityTypeHuman   IdentityType = "human"
	IdentityTypeService IdentityType = "service"
	IdentityTypeMachine IdentityType = "machine"
	IdentityTypeDevice  IdentityType = "device"
)

// Identity represents a principal in the system
type Identity struct {
	ID          ID           `json:"id"`
	Type        IdentityType `json:"type"`
	Name        string       `json:"name"`
	Email       string       `json:"email,omitempty"`
	PublicKey   []byte       `json:"public_key"`
	Fingerprint string       `json:"fingerprint"`
	CreatedAt   Timestamp    `json:"created_at"`
	UpdatedAt   Timestamp    `json:"updated_at"`
	ExpiresAt   *Timestamp   `json:"expires_at,omitempty"`
	Metadata    Metadata     `json:"metadata,omitempty"`
	Scopes      ScopeSet     `json:"-"`
	ScopeList   []Scope      `json:"scopes"`
	Status      EntityStatus `json:"status"`
	DeviceID    *ID          `json:"device_id,omitempty"`
	ParentID    *ID          `json:"parent_id,omitempty"`
	Provenance  *Provenance  `json:"provenance,omitempty"`
}

// EntityStatus represents the status of an entity
type EntityStatus string

const (
	StatusActive    EntityStatus = "active"
	StatusRevoked   EntityStatus = "revoked"
	StatusExpired   EntityStatus = "expired"
	StatusPending   EntityStatus = "pending"
	StatusSuspended EntityStatus = "suspended"
	StatusLocked    EntityStatus = "locked"
)

// Metadata represents arbitrary key-value metadata
type Metadata map[string]any

// Provenance tracks the origin and chain of custody
type Provenance struct {
	CreatedBy   ID                `json:"created_by"`
	CreatedAt   Timestamp         `json:"created_at"`
	CreatedFrom string            `json:"created_from"` // device fingerprint or source
	Chain       []ProvenanceEntry `json:"chain,omitempty"`
}

// ProvenanceEntry represents a single entry in the provenance chain
type ProvenanceEntry struct {
	Action    string    `json:"action"`
	ActorID   ID        `json:"actor_id"`
	Timestamp Timestamp `json:"timestamp"`
	Details   Metadata  `json:"details,omitempty"`
	Signature []byte    `json:"signature"`
}

// Session represents an authenticated session
type Session struct {
	ID            ID           `json:"id"`
	IdentityID    ID           `json:"identity_id"`
	DeviceID      ID           `json:"device_id"`
	Type          string       `json:"type"` // interactive, api, offline
	Scopes        ScopeSet     `json:"-"`
	ScopeList     []Scope      `json:"scopes"`
	CreatedAt     Timestamp    `json:"created_at"`
	ExpiresAt     Timestamp    `json:"expires_at"`
	LastActiveAt  Timestamp    `json:"last_active_at"`
	Fingerprint   string       `json:"fingerprint"`
	Status        EntityStatus `json:"status"`
	MFAVerified   bool         `json:"mfa_verified"`
	OfflineIssued bool         `json:"offline_issued"`
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return Now() > s.ExpiresAt
}

// IsActive checks if the session is active
func (s *Session) IsActive() bool {
	return s.Status == StatusActive && !s.IsExpired()
}

// Device represents a registered device
type Device struct {
	ID          ID           `json:"id"`
	OwnerID     ID           `json:"owner_id"`
	Name        string       `json:"name"`
	Type        string       `json:"type"` // desktop, mobile, server, etc.
	Fingerprint string       `json:"fingerprint"`
	PublicKey   []byte       `json:"public_key"`
	TrustScore  float64      `json:"trust_score"`
	AttestData  []byte       `json:"attest_data,omitempty"`
	CreatedAt   Timestamp    `json:"created_at"`
	LastSeenAt  Timestamp    `json:"last_seen_at"`
	Status      EntityStatus `json:"status"`
	Metadata    Metadata     `json:"metadata,omitempty"`
}

// SecretType represents the type of secret
type SecretType string

const (
	SecretTypeGeneric     SecretType = "generic"
	SecretTypePassword    SecretType = "password"
	SecretTypeAPIKey      SecretType = "api_key"
	SecretTypeCertificate SecretType = "certificate"
	SecretTypePrivateKey  SecretType = "private_key"
	SecretTypeToken       SecretType = "token"
	SecretTypeSSHKey      SecretType = "ssh_key"
	SecretTypeEnvVar      SecretType = "env_var"
)

// Secret represents a versioned secret
type Secret struct {
	ID          ID           `json:"id"`
	Name        string       `json:"name"`
	Type        SecretType   `json:"type"`
	Version     int          `json:"version"`
	Environment string       `json:"environment,omitempty"`
	CreatedAt   Timestamp    `json:"created_at"`
	UpdatedAt   Timestamp    `json:"updated_at"`
	ExpiresAt   *Timestamp   `json:"expires_at,omitempty"`
	AccessCount int          `json:"access_count"`
	ReadOnce    bool         `json:"read_once"`
	Immutable   bool         `json:"immutable"`
	RequireMFA  bool         `json:"require_mfa"`
	Status      EntityStatus `json:"status"`
	Metadata    Metadata     `json:"metadata,omitempty"`
	Provenance  *Provenance  `json:"provenance,omitempty"`
	// Encrypted fields - included in JSON as the whole struct is encrypted at storage layer
	EncryptedData []byte `json:"encrypted_data"`
	KeyID         ID     `json:"key_id"`
}

// SecretVersion represents a version of a secret
type SecretVersion struct {
	SecretID      ID        `json:"secret_id"`
	Version       int       `json:"version"`
	CreatedAt     Timestamp `json:"created_at"`
	CreatedBy     ID        `json:"created_by"`
	EncryptedData []byte    `json:"encrypted_data"`
	KeyID         ID        `json:"key_id"`
	Hash          []byte    `json:"hash"`
}

// EncryptedFile represents an encrypted file
type EncryptedFile struct {
	ID           ID           `json:"id"`
	Name         string       `json:"name"`
	OriginalName string       `json:"original_name"`
	Size         int64        `json:"size"`
	ChunkCount   int          `json:"chunk_count"`
	ContentType  string       `json:"content_type"`
	Hash         []byte       `json:"hash"`
	CreatedAt    Timestamp    `json:"created_at"`
	UpdatedAt    Timestamp    `json:"updated_at"`
	ExpiresAt    *Timestamp   `json:"expires_at,omitempty"`
	Sealed       bool         `json:"sealed"`
	Status       EntityStatus `json:"status"`
	Metadata     Metadata     `json:"metadata,omitempty"`
	Provenance   *Provenance  `json:"provenance,omitempty"`
	KeyID        ID           `json:"key_id"`
}

// FileChunk represents an encrypted chunk of a file
type FileChunk struct {
	FileID        ID     `json:"file_id"`
	Index         int    `json:"index"`
	EncryptedData []byte `json:"encrypted_data"`
	Hash          []byte `json:"hash"`
	Size          int    `json:"size"`
}

// Key represents a cryptographic key
type Key struct {
	ID             ID           `json:"id"`
	Type           KeyType      `json:"type"`
	Algorithm      string       `json:"algorithm"`
	Version        int          `json:"version"`
	Purpose        KeyPurpose   `json:"purpose"`
	CreatedAt      Timestamp    `json:"created_at"`
	ExpiresAt      *Timestamp   `json:"expires_at,omitempty"`
	RotatedAt      *Timestamp   `json:"rotated_at,omitempty"`
	DestroyedAt    *Timestamp   `json:"destroyed_at,omitempty"`
	Status         EntityStatus `json:"status"`
	ParentKeyID    *ID          `json:"parent_key_id,omitempty"`
	DeviceID       *ID          `json:"device_id,omitempty"`
	SessionID      *ID          `json:"session_id,omitempty"`
	HardwareBacked bool         `json:"hardware_backed"`
	Metadata       Metadata     `json:"metadata,omitempty"`
	// Key material - included in JSON as the whole struct is encrypted at storage layer
	Material []byte `json:"material"`
}

// KeyType represents the type of key
type KeyType string

const (
	KeyTypeMaster     KeyType = "master"
	KeyTypeEncryption KeyType = "encryption"
	KeyTypeSigning    KeyType = "signing"
	KeyTypeExchange   KeyType = "exchange"
	KeyTypeDerived    KeyType = "derived"
	KeyTypeSession    KeyType = "session"
	KeyTypeRecovery   KeyType = "recovery"
)

// KeyPurpose represents the intended use of a key
type KeyPurpose string

const (
	KeyPurposeEncrypt KeyPurpose = "encrypt"
	KeyPurposeDecrypt KeyPurpose = "decrypt"
	KeyPurposeSign    KeyPurpose = "sign"
	KeyPurposeVerify  KeyPurpose = "verify"
	KeyPurposeDerive  KeyPurpose = "derive"
	KeyPurposeWrap    KeyPurpose = "wrap"
	KeyPurposeUnwrap  KeyPurpose = "unwrap"
)

// Role represents an RBAC role
type Role struct {
	ID          ID           `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Scopes      ScopeSet     `json:"-"`
	ScopeList   []Scope      `json:"scopes"`
	ParentID    *ID          `json:"parent_id,omitempty"`
	CreatedAt   Timestamp    `json:"created_at"`
	UpdatedAt   Timestamp    `json:"updated_at"`
	Status      EntityStatus `json:"status"`
}

// AccessGrant represents a delegated access grant
type AccessGrant struct {
	ID              ID                `json:"id"`
	GrantorID       ID                `json:"grantor_id"`
	GranteeID       ID                `json:"grantee_id"`
	ResourceID      ID                `json:"resource_id"`
	ResourceType    string            `json:"resource_type"`
	Scopes          ScopeSet          `json:"-"`
	ScopeList       []Scope           `json:"scopes"`
	Conditions      *AccessConditions `json:"conditions,omitempty"`
	CreatedAt       Timestamp         `json:"created_at"`
	ExpiresAt       *Timestamp        `json:"expires_at,omitempty"`
	RevokedAt       *Timestamp        `json:"revoked_at,omitempty"`
	Status          EntityStatus      `json:"status"`
	DelegationChain []ID              `json:"delegation_chain,omitempty"`
	Resharing       bool              `json:"resharing_allowed"`
}

// AccessConditions represents conditional access requirements
type AccessConditions struct {
	DeviceIDs       []ID         `json:"device_ids,omitempty"`
	IPRanges        []string     `json:"ip_ranges,omitempty"`
	TimeWindows     []TimeWindow `json:"time_windows,omitempty"`
	RequireMFA      bool         `json:"require_mfa"`
	RequireApproval bool         `json:"require_approval"`
	ApproverIDs     []ID         `json:"approver_ids,omitempty"`
	MaxAccessCount  int          `json:"max_access_count,omitempty"`
	Locations       []string     `json:"locations,omitempty"`
}

// TimeWindow represents a time-based access window
type TimeWindow struct {
	StartTime string `json:"start_time"` // HH:MM format
	EndTime   string `json:"end_time"`   // HH:MM format
	Days      []int  `json:"days"`       // 0=Sunday
	Timezone  string `json:"timezone"`
}

// AccessRequestStatus represents the status of an access request
type AccessRequestStatus string

const (
	AccessRequestStatusPending  AccessRequestStatus = "pending"
	AccessRequestStatusApproved AccessRequestStatus = "approved"
	AccessRequestStatusDenied   AccessRequestStatus = "denied"
	AccessRequestStatusExpired  AccessRequestStatus = "expired"
	AccessRequestStatusRevoked  AccessRequestStatus = "revoked"
)

// AccessRequest represents a Just-In-Time access request
type AccessRequest struct {
	ID            ID                  `json:"id"`
	RequestorID   ID                  `json:"requestor_id"`
	ResourceID    ID                  `json:"resource_id"`
	ResourceType  string              `json:"resource_type"`
	Role          string              `json:"role,omitempty"`
	Permissions   []string            `json:"permissions,omitempty"`
	Justification string              `json:"justification"`
	Duration      string              `json:"duration"` // Requested duration e.g. "2h"
	Status        AccessRequestStatus `json:"status"`
	ApproverIDs   []ID                `json:"approver_ids,omitempty"`
	MinApprovals  int                 `json:"min_approvals"`
	ApprovalCount int                 `json:"approval_count"`
	ReviewerNotes string              `json:"reviewer_notes,omitempty"`
	CreatedAt     Timestamp           `json:"created_at"`
	UpdatedAt     Timestamp           `json:"updated_at"`
	ExpiresAt     Timestamp           `json:"expires_at"`                // When the request expires
	AccessGrantID *ID                 `json:"access_grant_id,omitempty"` // ID of created grant if approved
}

// Policy represents an access policy
type Policy struct {
	ID          ID           `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Version     int          `json:"version"`
	Type        PolicyType   `json:"type"`
	Rules       []PolicyRule `json:"rules"`
	CreatedAt   Timestamp    `json:"created_at"`
	UpdatedAt   Timestamp    `json:"updated_at"`
	Status      EntityStatus `json:"status"`
	Signature   []byte       `json:"signature"`
	SignedBy    ID           `json:"signed_by"`
}

// PolicyType represents the type of policy
type PolicyType string

const (
	PolicyTypeAccess     PolicyType = "access"
	PolicyTypeRotation   PolicyType = "rotation"
	PolicyTypeRetention  PolicyType = "retention"
	PolicyTypeApproval   PolicyType = "approval"
	PolicyTypeCompliance PolicyType = "compliance"
)

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	ID         ID       `json:"id"`
	Effect     string   `json:"effect"` // allow, deny
	Actions    []string `json:"actions"`
	Resources  []string `json:"resources"`
	Conditions Metadata `json:"conditions,omitempty"`
	Priority   int      `json:"priority"`
}

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID           ID        `json:"id"`
	Type         string    `json:"type"`
	Action       string    `json:"action"`
	ActorID      ID        `json:"actor_id"`
	ActorType    string    `json:"actor_type"`
	ResourceID   *ID       `json:"resource_id,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	SessionID    *ID       `json:"session_id,omitempty"`
	DeviceID     *ID       `json:"device_id,omitempty"`
	Timestamp    Timestamp `json:"timestamp"`
	Success      bool      `json:"success"`
	Details      Metadata  `json:"details,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	PreviousHash []byte    `json:"previous_hash"`
	Hash         []byte    `json:"hash"`
	Signature    []byte    `json:"signature,omitempty"`
}

// Organization represents a tenant organization
type Organization struct {
	ID        ID           `json:"id"`
	Name      string       `json:"name"`
	Slug      string       `json:"slug"`
	OwnerID   ID           `json:"owner_id"`
	CreatedAt Timestamp    `json:"created_at"`
	UpdatedAt Timestamp    `json:"updated_at"`
	Status    EntityStatus `json:"status"`
	Settings  OrgSettings  `json:"settings"`
	Metadata  Metadata     `json:"metadata,omitempty"`
}

// OrgSettings represents organization settings
type OrgSettings struct {
	ComplianceMode   string   `json:"compliance_mode,omitempty"` // SOC2, HIPAA, etc.
	RequireMFA       bool     `json:"require_mfa"`
	SessionTimeout   int      `json:"session_timeout_minutes"`
	PasswordPolicy   Metadata `json:"password_policy,omitempty"`
	AllowedDomains   []string `json:"allowed_domains,omitempty"`
	LegalHoldEnabled bool     `json:"legal_hold_enabled"`
	IncidentFrozen   bool     `json:"incident_frozen"`
}

// Team represents a team within an organization
type Team struct {
	ID          ID           `json:"id"`
	OrgID       ID           `json:"org_id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	ParentID    *ID          `json:"parent_id,omitempty"`
	CreatedAt   Timestamp    `json:"created_at"`
	UpdatedAt   Timestamp    `json:"updated_at"`
	Status      EntityStatus `json:"status"`
}

// Environment represents a deployment environment
type Environment struct {
	ID          ID           `json:"id"`
	OrgID       ID           `json:"org_id"`
	Name        string       `json:"name"` // prod, staging, dev
	Description string       `json:"description"`
	Protected   bool         `json:"protected"`
	CreatedAt   Timestamp    `json:"created_at"`
	Status      EntityStatus `json:"status"`
}

// Incident represents a security incident
type Incident struct {
	ID          ID              `json:"id"`
	OrgID       ID              `json:"org_id"`
	Type        string          `json:"type"`
	Severity    string          `json:"severity"` // critical, high, medium, low
	DeclaredBy  ID              `json:"declared_by"`
	DeclaredAt  Timestamp       `json:"declared_at"`
	ResolvedAt  *Timestamp      `json:"resolved_at,omitempty"`
	Status      EntityStatus    `json:"status"`
	Description string          `json:"description"`
	Timeline    []IncidentEvent `json:"timeline"`
	Evidence    []ID            `json:"evidence,omitempty"` // audit event IDs
}

// IncidentEvent represents an event in incident timeline
type IncidentEvent struct {
	Timestamp   Timestamp `json:"timestamp"`
	ActorID     ID        `json:"actor_id"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
}

// Backup represents an encrypted backup
type Backup struct {
	ID           ID           `json:"id"`
	Type         string       `json:"type"` // full, incremental
	CreatedAt    Timestamp    `json:"created_at"`
	CreatedBy    ID           `json:"created_by"`
	Size         int64        `json:"size"`
	Hash         []byte       `json:"hash"`
	EncryptedKey []byte       `json:"encrypted_key"`
	Status       EntityStatus `json:"status"`
	Metadata     Metadata     `json:"metadata,omitempty"`
}

// Share represents a secure share
type Share struct {
	ID             ID           `json:"id"`
	Type           string       `json:"type"` // secret, file
	ResourceID     ID           `json:"resource_id"`
	CreatorID      ID           `json:"creator_id"`
	RecipientID    *ID          `json:"recipient_id,omitempty"`
	RecipientKey   []byte       `json:"recipient_key,omitempty"` // for external shares
	CreatedAt      Timestamp    `json:"created_at"`
	ExpiresAt      *Timestamp   `json:"expires_at,omitempty"`
	AccessedAt     *Timestamp   `json:"accessed_at,omitempty"`
	RevokedAt      *Timestamp   `json:"revoked_at,omitempty"`
	MaxAccess      int          `json:"max_access,omitempty"`
	AccessCount    int          `json:"access_count"`
	OneTime        bool         `json:"one_time"`
	Status         EntityStatus `json:"status"`
	ProofOfReceipt []byte       `json:"proof_of_receipt,omitempty"`
	Metadata       Metadata     `json:"metadata,omitempty"`
}

// VendorAccess represents vendor access configuration
type VendorAccess struct {
	ID         ID           `json:"id"`
	OrgID      ID           `json:"org_id"`
	VendorID   ID           `json:"vendor_id"`
	VendorName string       `json:"vendor_name"`
	Resources  []ID         `json:"resources"`
	Scopes     ScopeSet     `json:"-"`
	ScopeList  []Scope      `json:"scopes"`
	ApprovedBy ID           `json:"approved_by"`
	ApprovedAt Timestamp    `json:"approved_at"`
	ExpiresAt  *Timestamp   `json:"expires_at,omitempty"`
	RevokedAt  *Timestamp   `json:"revoked_at,omitempty"`
	CreatedAt  Timestamp    `json:"created_at"`
	Status     EntityStatus `json:"status"`
	Metadata   Metadata     `json:"metadata,omitempty"`
}

// TransferStatus represents the status of a transfer workflow
type TransferStatus string

const (
	TransferStatusPending    TransferStatus = "pending"
	TransferStatusApproved   TransferStatus = "approved"
	TransferStatusInProgress TransferStatus = "in_progress"
	TransferStatusCompleted  TransferStatus = "completed"
	TransferStatusFailed     TransferStatus = "failed"
	TransferStatusCancelled  TransferStatus = "cancelled"
)

// TransferWorkflow represents an M&A transfer workflow
type TransferWorkflow struct {
	ID                ID             `json:"id"`
	SourceOrgID       ID             `json:"source_org_id"`
	TargetOrgID       ID             `json:"target_org_id"`
	Status            TransferStatus `json:"status"`
	Resources         []ID           `json:"resources"`
	TransferredAt     *Timestamp     `json:"transferred_at,omitempty"`
	InitiatedBy       ID             `json:"initiated_by"`
	RequiredApprovals int            `json:"required_approvals"`
	ApprovedBy        []ID           `json:"approved_by"`
	CreatedAt         Timestamp      `json:"created_at"`
	UpdatedAt         Timestamp      `json:"updated_at"`
	Metadata          Metadata       `json:"metadata,omitempty"`
}

// SSHProfile represents an SSH connection profile
type SSHProfile struct {
	ID            ID           `json:"id"`
	Name          string       `json:"name"`
	Host          string       `json:"host"`
	Port          int          `json:"port"`
	User          string       `json:"user"`
	IdentityKeyID ID           `json:"identity_key_id"`
	OwnerID       ID           `json:"owner_id"`
	Options       Metadata     `json:"options,omitempty"`
	CreatedAt     Timestamp    `json:"created_at"`
	UpdatedAt     Timestamp    `json:"updated_at"`
	Status        EntityStatus `json:"status"`
}

// SSHSession represents an active SSH session
type SSHSession struct {
	ID           ID         `json:"id"`
	ProfileID    ID         `json:"profile_id"`
	IdentityID   ID         `json:"identity_id"`
	StartedAt    Timestamp  `json:"started_at"`
	EndedAt      *Timestamp `json:"ended_at,omitempty"`
	Status       string     `json:"status"` // active, ended, terminated
	CommandCount int        `json:"command_count"`
	Metadata     Metadata   `json:"metadata,omitempty"`
}

// PipelineProvider represents a CI/CD provider
type PipelineProvider string

const (
	PipelineProviderGitHub    PipelineProvider = "github"
	PipelineProviderGitLab    PipelineProvider = "gitlab"
	PipelineProviderJenkins   PipelineProvider = "jenkins"
	PipelineProviderCircleCI  PipelineProvider = "circleci"
	PipelineProviderBitbucket PipelineProvider = "bitbucket"
	PipelineProviderGeneric   PipelineProvider = "generic"
)

// PipelineIdentity represents a CI/CD pipeline identity
type PipelineIdentity struct {
	ID             ID               `json:"id"`
	Name           string           `json:"name"`
	Provider       PipelineProvider `json:"provider"`
	RepositoryID   string           `json:"repository_id"`
	BranchPatterns []string         `json:"branch_patterns"`
	AllowedSecrets []ID             `json:"allowed_secrets"`
	SecretPatterns []string         `json:"secret_patterns"`
	PolicyID       *ID              `json:"policy_id,omitempty"`
	OrgID          ID               `json:"org_id"`
	CreatedAt      Timestamp        `json:"created_at"`
	UpdatedAt      Timestamp        `json:"updated_at"`
	Status         EntityStatus     `json:"status"`
	Metadata       Metadata         `json:"metadata,omitempty"`
}

// PipelinePolicy represents CI/CD-specific policies
type PipelinePolicy struct {
	ID                  ID           `json:"id"`
	Name                string       `json:"name"`
	Description         string       `json:"description"`
	RequiredApprovals   int          `json:"required_approvals"`
	AllowedEnvironments []string     `json:"allowed_environments"`
	BranchRestrictions  []string     `json:"branch_restrictions"`
	MaxSecretAge        int64        `json:"max_secret_age_seconds"`
	RequireRotation     bool         `json:"require_rotation"`
	CreatedAt           Timestamp    `json:"created_at"`
	UpdatedAt           Timestamp    `json:"updated_at"`
	Status              EntityStatus `json:"status"`
}

// AutomationStep represents a single action in an automation pipeline
type AutomationStep struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"` // e.g., "secret:create", "org:add_member"
	Parameters map[string]string `json:"parameters"`
	Condition  string            `json:"condition,omitempty"`
}

// AutomationPipeline represents a robust configuration for automated workflows
type AutomationPipeline struct {
	ID          ID               `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Trigger     string           `json:"trigger"` // e.g., "enrollment", "promotion"
	Steps       []AutomationStep `json:"steps"`
	OrgID       ID               `json:"org_id"`
	CreatedAt   Timestamp        `json:"created_at"`
	UpdatedAt   Timestamp        `json:"updated_at"`
	Status      EntityStatus     `json:"status"`
	Metadata    Metadata         `json:"metadata,omitempty"`
}

// Error represents a structured error
type Error struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details Metadata `json:"details,omitempty"`
}

func (e *Error) Error() string {
	if e.Details != nil {
		details, _ := json.Marshal(e.Details)
		return e.Code + ": " + e.Message + " - " + string(details)
	}
	return e.Code + ": " + e.Message
}

// Error codes
const (
	ErrCodeUnauthorized             = "unauthorized"
	ErrCodeForbidden                = "forbidden"
	ErrCodeNotFound                 = "not_found"
	ErrCodeConflict                 = "conflict"
	ErrCodeValidation               = "validation_error"
	ErrCodeCrypto                   = "crypto_error"
	ErrCodeStorage                  = "storage_error"
	ErrCodePolicy                   = "policy_violation"
	ErrCodeExpired                  = "expired"
	ErrCodeRevoked                  = "revoked"
	ErrCodeRateLimited              = "rate_limited"
	ErrCodeIncidentFrozen           = "incident_frozen"
	ErrCodeScopeRequired            = "scope_required"
	ErrCodeEntitlementScopeRequired = "entitlement_scope_required"
	ErrCodeEntitlementDenied        = "entitlement_denied"
	ErrCodeEntitlementLimitExceeded = "entitlement_limit_exceeded"
	ErrCodeACLDenied                = "acl_denied"
	ErrCodeAuthzSpecMissing         = "authz_spec_missing"
)

// NewError creates a new error
func NewError(code, message string, details ...Metadata) *Error {
	e := &Error{Code: code, Message: message}
	if len(details) > 0 {
		e.Details = details[0]
	}
	return e
}

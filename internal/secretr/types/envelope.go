package types

// Envelope structures
type Envelope struct {
	ID           ID              `json:"id"`
	Version      int             `json:"version"`
	Header       EnvelopeHeader  `json:"header"`
	EncryptedKey []byte          `json:"encrypted_key"` // DEK encrypted for recipient
	Payload      []byte          `json:"payload"`       // Encrypted EnvelopePayload
	Signature    []byte          `json:"signature"`
	Custody      []CustodyEntry  `json:"custody"`
}

type EnvelopeHeader struct {
	SenderID      ID            `json:"sender_id"`
	RecipientID   ID            `json:"recipient_id"`
	PolicyID      ID            `json:"policy_id,omitempty"`
	BusinessRules BusinessRules `json:"business_rules"`
	CreatedAt     Timestamp     `json:"created_at"`
	ExpiresAt     Timestamp     `json:"expires_at"`
}

type EnvelopePayload struct {
	Secrets []SecretPayload `json:"secrets,omitempty"`
	Files   []FilePayload   `json:"files,omitempty"`
	Message string          `json:"message,omitempty"`
}

type SecretPayload struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
	Type  string `json:"type"`
}

type FilePayload struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
	Type string `json:"type"`
	Metadata Metadata `json:"metadata,omitempty"`
}

type CustodyEntry struct {
	Hash      []byte    `json:"hash"` // Chain hash
	Action    string    `json:"action"`
	ActorID   ID        `json:"actor_id"`
	Timestamp Timestamp `json:"timestamp"`
	Location  string    `json:"location"`
	Signature []byte    `json:"signature"`
}

type BusinessRules struct {
	AllowedTimeWindows []TimeWindow `json:"allowed_time_windows,omitempty"`
	AllowedIPRanges    []string     `json:"allowed_ip_ranges,omitempty"`
	RequiredTrustLevel float64      `json:"required_trust_level,omitempty"`
	RequireMFA         bool         `json:"require_mfa,omitempty"`
	MaxAccessCount     int          `json:"max_access_count,omitempty"`
}



const (
	ActionEnvelopeCreate = "create"
	ActionEnvelopeSend   = "send"
	ActionEnvelopeOpen   = "open"
	ActionEnvelopeReject = "reject"
)

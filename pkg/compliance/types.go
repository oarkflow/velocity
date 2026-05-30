package compliance

import "time"

// KVStore is the small storage surface needed by compliance managers.
type KVStore interface {
	Put(key, value []byte) error
	Get(key []byte) ([]byte, error)
	Keys(pattern string) ([]string, error)
}

// Framework identifies a regulatory framework.
type Framework string

const (
	FrameworkHIPAA    Framework = "HIPAA"
	FrameworkGDPR     Framework = "GDPR"
	FrameworkNIST     Framework = "NIST_800_53"
	FrameworkFIPS     Framework = "FIPS_140_2"
	FrameworkPCIDSS   Framework = "PCI_DSS"
	FrameworkSOC2     Framework = "SOC2_TYPE2"
	FrameworkISO27001 Framework = "ISO_27001"
)

// DataClassification defines sensitivity levels.
type DataClassification string

const (
	DataClassPublic       DataClassification = "public"
	DataClassInternal     DataClassification = "internal"
	DataClassConfidential DataClassification = "confidential"
	DataClassRestricted   DataClassification = "restricted"
	DataClassTopSecret    DataClassification = "top_secret"
)

// ConsentRecord tracks consent for data processing.
type ConsentRecord struct {
	ConsentID       string     `json:"consent_id"`
	Purpose         string     `json:"purpose"`
	GrantedAt       time.Time  `json:"granted_at"`
	WithdrawnAt     *time.Time `json:"withdrawn_at,omitempty"`
	LegalBasis      string     `json:"legal_basis"`
	ProcessingScope []string   `json:"processing_scope"`
	Version         string     `json:"version"`
	Active          bool       `json:"active"`
}

type ConsentManager struct {
	store KVStore
}

func NewConsentManager(store KVStore) *ConsentManager {
	return &ConsentManager{store: store}
}

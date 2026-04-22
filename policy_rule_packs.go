package velocity

import (
	"context"
	"fmt"
)

const (
	PolicyPackGDPR = "gdpr-default"
	PolicyPackHIPAA = "hipaa-default"
	PolicyPackPCI = "pci-default"
)

// InstallPolicyPack installs a predefined policy pack.
func (pe *PolicyEngine) InstallPolicyPack(ctx context.Context, pack string) error {
	switch pack {
	case PolicyPackGDPR:
		return pe.installPolicies(ctx, gdprDefaultPolicies())
	case PolicyPackHIPAA:
		return pe.installPolicies(ctx, hipaaDefaultPolicies())
	case PolicyPackPCI:
		return pe.installPolicies(ctx, pciDefaultPolicies())
	default:
		return fmt.Errorf("unknown policy pack: %s", pack)
	}
}

func (pe *PolicyEngine) installPolicies(ctx context.Context, policies []*CompliancePolicy) error {
	for _, policy := range policies {
		if err := pe.AddPolicy(ctx, policy); err != nil {
			return err
		}
	}
	return nil
}

// InstallDefaultPacks installs the default GDPR, HIPAA, and PCI packs.
func (pe *PolicyEngine) InstallDefaultPacks(ctx context.Context) error {
	if err := pe.InstallPolicyPack(ctx, PolicyPackGDPR); err != nil {
		return err
	}
	if err := pe.InstallPolicyPack(ctx, PolicyPackHIPAA); err != nil {
		return err
	}
	if err := pe.InstallPolicyPack(ctx, PolicyPackPCI); err != nil {
		return err
	}
	return nil
}

func gdprDefaultPolicies() []*CompliancePolicy {
	return []*CompliancePolicy{
		{
			PolicyID:    "gdpr-encryption",
			Name:        "GDPR Encryption for Confidential Data",
			Framework:   FrameworkGDPR,
			Enabled:     true,
			EnforcementMode: "enforce",
			Rules: []PolicyRule{
				{
					RuleID:   "gdpr-encrypt-confidential",
					Action:   "deny",
					Severity: "high",
					Parameters: map[string]interface{}{
						"operations":        []interface{}{"write"},
						"min_data_class":    string(DataClassConfidential),
						"require_encryption": true,
					},
				},
			},
		},
		{
			PolicyID:    "gdpr-mfa-restricted",
			Name:        "GDPR MFA for Restricted Data",
			Framework:   FrameworkGDPR,
			Enabled:     true,
			EnforcementMode: "enforce",
			Rules: []PolicyRule{
				{
					RuleID:   "gdpr-mfa-restricted-read",
					Action:   "deny",
					Severity: "critical",
					Parameters: map[string]interface{}{
						"operations":     []interface{}{"read"},
						"min_data_class": string(DataClassRestricted),
						"require_mfa":    true,
					},
				},
			},
		},
	}
}

func hipaaDefaultPolicies() []*CompliancePolicy {
	return []*CompliancePolicy{
		{
			PolicyID:    "hipaa-phi-encryption",
			Name:        "HIPAA PHI Encryption",
			Framework:   FrameworkHIPAA,
			Enabled:     true,
			EnforcementMode: "enforce",
			Rules: []PolicyRule{
				{
					RuleID:   "hipaa-phi-encrypt",
					Action:   "deny",
					Severity: "critical",
					Parameters: map[string]interface{}{
						"operations":        []interface{}{"write"},
						"min_data_class":    string(DataClassRestricted),
						"require_encryption": true,
					},
				},
			},
		},
		{
			PolicyID:    "hipaa-minimum-necessary",
			Name:        "HIPAA Minimum Necessary Access",
			Framework:   FrameworkHIPAA,
			Enabled:     true,
			EnforcementMode: "monitor",
			Rules: []PolicyRule{
				{
					RuleID:   "hipaa-minimum-necessary-read",
					Action:   "alert",
					Severity: "medium",
					Parameters: map[string]interface{}{
						"operations":     []interface{}{"read"},
						"min_data_class": string(DataClassRestricted),
					},
				},
			},
		},
	}
}

func pciDefaultPolicies() []*CompliancePolicy {
	return []*CompliancePolicy{
		{
			PolicyID:    "pci-mfa",
			Name:        "PCI MFA for Cardholder Data",
			Framework:   FrameworkPCIDSS,
			Enabled:     true,
			EnforcementMode: "enforce",
			Rules: []PolicyRule{
				{
					RuleID:   "pci-mfa-required",
					Action:   "deny",
					Severity: "critical",
					Parameters: map[string]interface{}{
						"operations":  []interface{}{"read", "write", "delete"},
						"require_mfa": true,
					},
				},
			},
		},
		{
			PolicyID:    "pci-encryption",
			Name:        "PCI Encryption Required",
			Framework:   FrameworkPCIDSS,
			Enabled:     true,
			EnforcementMode: "enforce",
			Rules: []PolicyRule{
				{
					RuleID:   "pci-encrypt",
					Action:   "deny",
					Severity: "high",
					Parameters: map[string]interface{}{
						"operations":        []interface{}{"write"},
						"min_data_class":    string(DataClassRestricted),
						"require_encryption": true,
					},
				},
			},
		},
	}
}

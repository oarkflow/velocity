package velocity

import "context"

// GrantConsent records consent for a GDPR subject.
func (gc *GDPRController) GrantConsent(ctx context.Context, subjectID string, record ConsentRecord) error {
	if gc.consentMgr == nil {
		return nil
	}
	return gc.consentMgr.GrantConsent(ctx, subjectID, record)
}

// WithdrawConsent withdraws a consent record.
func (gc *GDPRController) WithdrawConsent(ctx context.Context, subjectID, consentID string) error {
	if gc.consentMgr == nil {
		return nil
	}
	return gc.consentMgr.WithdrawConsent(ctx, subjectID, consentID)
}

// ListConsents lists all consents for a subject.
func (gc *GDPRController) ListConsents(ctx context.Context, subjectID string) ([]ConsentRecord, error) {
	if gc.consentMgr == nil {
		return nil, nil
	}
	return gc.consentMgr.ListConsents(ctx, subjectID)
}

// HasActiveConsent checks if a subject has an active consent for a purpose.
func (gc *GDPRController) HasActiveConsent(ctx context.Context, subjectID, purpose string) (bool, *ConsentRecord, error) {
	if gc.consentMgr == nil {
		return false, nil, nil
	}
	return gc.consentMgr.HasActiveConsent(ctx, subjectID, purpose)
}

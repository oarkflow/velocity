package compliance

import (
	"fmt"
	"time"
)

// Storage key scheme for everything this plugin persists via the looked-up
// api.StorageBackend. All keys live under the "compliance/" namespace so
// they never collide with kv/object/secret key spaces sharing the same
// backend.
func auditKey(seq int) string {
	return fmt.Sprintf("compliance/audit/%012d", seq)
}

const auditHeadKey = "compliance/audit/head"

func legalHoldKey(resource string) string {
	return "compliance/legalhold/" + resource
}

func retentionKey(resource string) string {
	return "compliance/retention/" + resource
}

func consentKey(subject, purpose string) string {
	return "compliance/consent/" + subject + "/" + purpose
}

func classificationKey(resource string) string {
	return "compliance/class/" + resource
}

// residencyRulePrefix scans every stored ResidencyRule; the key includes
// the rule's ResourcePrefix so rules are naturally ordered and each
// ResourcePrefix has at most one rule (SetResidencyRule overwrites).
const residencyRulePrefix = "compliance/residency/rule/"

func residencyRuleKey(resourcePrefix string) string {
	return residencyRulePrefix + resourcePrefix
}

func lineagePrefix(resource string) string {
	return "compliance/lineage/" + resource + "/"
}

// lineageKey zero-pads the nanosecond timestamp so Scan returns events in
// chronological order for a given resource.
func lineageKey(resource string, at time.Time) string {
	return fmt.Sprintf("%s%020d", lineagePrefix(resource), at.UnixNano())
}

const violationPrefix = "compliance/violation/"

func violationResourcePrefix(resource string) string {
	if resource == "" {
		return violationPrefix
	}
	return violationPrefix + resource + "/"
}

func violationKey(resource string, at time.Time, seq uint64) string {
	return fmt.Sprintf("%s%020d-%020d", violationResourcePrefix(resource), at.UnixNano(), seq)
}

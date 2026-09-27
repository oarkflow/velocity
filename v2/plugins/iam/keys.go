package iam

import "fmt"

// Storage key scheme (all under the looked-up api.StorageBackend):
//   iam/policy/<name>            -> JSON-encoded IAMPolicy
//   iam/attach/<subject>/<name>  -> empty marker value (presence = attached)
//
// Attachment keys are scoped under the subject first so ListAttached(subject)
// is a single prefix Scan; policy names never contain "/" (rejected at
// PutPolicy) so this layout has no ambiguity between the two key families.

func policyKey(name string) []byte {
	return []byte("iam/policy/" + name)
}

const policyPrefix = "iam/policy/"

func attachKey(subject, policyName string) []byte {
	return []byte(fmt.Sprintf("iam/attach/%s/%s", subject, policyName))
}

func attachPrefix(subject string) string {
	return fmt.Sprintf("iam/attach/%s/", subject)
}

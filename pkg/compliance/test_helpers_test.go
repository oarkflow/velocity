package compliance_test

import "github.com/oarkflow/velocity/pkg/compliance"

func containsFramework(frameworks []compliance.Framework, target compliance.Framework) bool {
	for _, framework := range frameworks {
		if framework == target {
			return true
		}
	}
	return false
}

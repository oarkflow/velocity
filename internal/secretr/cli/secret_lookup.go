package cli

import (
	"encoding/json"
	"fmt"
	"strings"
)

// LookupVelocitySecretValue resolves a secret from the Velocity-backed store.
// It supports:
// - "name" -> category defaults to "general"
// - "category:name"
// - dot-notation nested reads, e.g. "processgate.aws.client_id"
func LookupVelocitySecretValue(name string) (string, bool, error) {
	adapter := GetGlobalAdapter()
	if adapter == nil || adapter.GetVelocityDB() == nil {
		return "", false, nil
	}

	category, keyPath := parseSecretLookup(name)
	root := keyPath
	nestedPath := ""
	if idx := strings.Index(keyPath, "."); idx >= 0 {
		root = keyPath[:idx]
		nestedPath = keyPath[idx+1:]
	}
	storageKey := fmt.Sprintf("secret:%s:%s", category, root)
	raw, err := adapter.GetVelocityDB().Get([]byte(storageKey))
	if err != nil {
		return "", false, nil
	}
	if nestedPath == "" {
		return string(raw), true, nil
	}

	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", false, fmt.Errorf("failed to parse secret %q as json for nested lookup", name)
	}
	val, ok := getNestedJSONValue(data, strings.Split(nestedPath, "."))
	if !ok {
		return "", false, nil
	}
	return stringifyJSONScalar(val), true, nil
}

func parseSecretLookup(name string) (category, keyPath string) {
	n := strings.TrimSpace(name)
	category = "general"
	keyPath = n
	if idx := strings.Index(n, ":"); idx > 0 && idx+1 < len(n) {
		category = strings.TrimSpace(n[:idx])
		keyPath = strings.TrimSpace(n[idx+1:])
	}
	if category == "" {
		category = "general"
	}
	return category, keyPath
}

func getNestedJSONValue(data any, path []string) (any, bool) {
	if len(path) == 0 {
		return data, true
	}
	m, ok := data.(map[string]any)
	if !ok {
		return nil, false
	}
	next, exists := m[path[0]]
	if !exists {
		return nil, false
	}
	return getNestedJSONValue(next, path[1:])
}

func stringifyJSONScalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", x), "0"), ".")
	default:
		return fmt.Sprint(x)
	}
}

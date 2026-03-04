package types

import "encoding/json"

// MarshalJSON is a helper for JSON marshaling
func MarshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// UnmarshalJSON is a helper for JSON unmarshaling
func UnmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

package velocity

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestFastJSONScalarFieldMatchesTopLevelSemantics(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		field string
		want  any
		ok    bool
	}{
		{name: "top-level after nested shadow", raw: `{"nested":{"age":99},"age":40}`, field: "age", want: float64(40), ok: true},
		{name: "escaped key", raw: `{"a\nb":"value"}`, field: "a\nb", want: "value", ok: true},
		{name: "escaped value", raw: `{"name":"Ali\u0063e"}`, field: "name", want: "Alice", ok: true},
		{name: "missing nested only", raw: `{"nested":{"age":99}}`, field: "age", ok: false},
		{name: "object value is not scalar", raw: `{"profile":{"age":40}}`, field: "profile", ok: false},
		{name: "array value is not scalar", raw: `{"tags":["a","b"]}`, field: "tags", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := fastJSONScalarField([]byte(tt.raw), tt.field)
			if ok != tt.ok {
				t.Fatalf("ok=%v, want %v; got=%#v", ok, tt.ok, got)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("value=%#v, want %#v", got, tt.want)
			}
		})
	}
}

func FuzzFastJSONScalarFieldMatchesEncodingJSON(f *testing.F) {
	for _, seed := range []string{
		`{"id":1,"name":"Alice","age":30}`,
		`{"nested":{"age":99},"age":40}`,
		`{"name":"Ali\u0063e","active":true}`,
		`{"name":null,"age":25}`,
		`{"tags":["x"],"age":35}`,
	} {
		f.Add(seed, "age")
	}

	f.Fuzz(func(t *testing.T, raw string, field string) {
		if field == "" || len(raw) > 4096 {
			return
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			return
		}
		want, exists := decoded[field]
		switch want.(type) {
		case string, float64, bool, nil:
		default:
			exists = false
		}

		got, ok := fastJSONScalarField([]byte(raw), field)
		if ok != exists {
			t.Fatalf("ok=%v, want %v for raw=%s field=%q got=%#v decoded=%#v", ok, exists, raw, field, got, decoded[field])
		}
		if !exists {
			return
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("got=%#v want=%#v for raw=%s field=%q", got, want, raw, field)
		}
	})
}

package sql

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// decodeRowJSONParityCases: every input here is decoded BOTH by
// decodeRowJSON and by encoding/json into api.Row; results must be
// reflect.DeepEqual, and errors (nil or not) must agree — including
// malformed input. These cases were chosen to attack every branch of the
// fast parser: escapes, unicode, surrogate pairs, number shapes,
// literals, nesting, whitespace, duplicate keys, and malformed tails.
func TestDecodeRowJSONParityWithEncodingJSON(t *testing.T) {
	cases := []string{
		`{}`,
		`{ }`,
		`  {"a":1 }  `,
		`{"id":1,"name":"user-1","age":42}`,
		`{"id":1.5,"neg":-2.25,"exp":1e3,"expn":1.5e-3,"big":123456789.003}`,
		`{"t":true,"f":false,"n":null}`,
		`{"empty":"","unicode":"héllo","tab":"a\tb","quote":"s\u0061y \"hi\""}`,
		`{"emoji":"😀","pair":"\ud83d\ude00","lone":"\ud800"}`,
		`{"ctrl":"line\nbreak"}`,
		`{"slash":"a\/b","back":"c\\d"}`,
		`{"dup":1,"dup":2}`,
		`{"nested":{"x":1},"arr":[1,2,3],"deep":{"a":{"b":[true,null]}}}`,
		`{"mixed":{},"emptyArr":[]}`,
		`{"key with spaces and .dots.and:colons":1}`,
		`{"z":0,"a":0}`,
	}
	// Deliberately malformed inputs: errors must agree too.
	cases = append(cases,
		`{"a":1,}`,    // trailing comma
		`{"a":1}}`,    // trailing junk
		`{"a"}`,       // missing value
		`{"a" 1}`,     // missing colon
		`[1,2]`,       // not an object -> nil row in both paths
		`{"a":1e999}`, // number overflow
		`{"a":"unterminated`, `{"a":"bad control
char"}`,
		`{"a":TRUE}`,
		`{"a":-}`,
		"", // empty
	)

	for _, in := range cases {
		wantRow, wantErr := unmarshalRowReference(in)
		gotRow, gotErr := decodeRowJSON([]byte(in))

		if (wantErr != nil) != (gotErr != nil) {
			t.Errorf("input %q: error mismatch: want %v, got %v", in, wantErr, gotErr)
			continue
		}
		if wantErr != nil {
			if wantErr.Error() != gotErr.Error() {
				t.Errorf("input %q: error text mismatch:\n want %q\n got  %q", in, wantErr, gotErr)
			}
			continue
		}
		if !reflect.DeepEqual(api.Row(gotRow), api.Row(wantRow)) {
			t.Errorf("input %q: value mismatch:\n want %#v\n got  %#v", in, wantRow, gotRow)
		}
	}
}

// unmarshalRowReference performs the ORIGINAL row decode the engine used
// before decodeRowJSON: json.Unmarshal(data, &row).
func unmarshalRowReference(data string) (api.Row, error) {
	var row api.Row
	if err := json.Unmarshal([]byte(data), &row); err != nil {
		return row, err
	}
	return row, nil
}

// TestDecodeRowJSONRandomParity fuzzes structured random rows through
// both the fast decoder and encoding/json and requires exact equality.
func TestDecodeRowJSONRandomParity(t *testing.T) {
	seedRows := []api.Row{
		{"id": float64(7), "name": "user-7", "flag": true, "saldo": -12.5},
		{"id": float64(8), "note": "line\nwith\ttabs and \"quotes\"", "lvl": 0.0001},
		{"id": float64(9), "emoji": "🚀", "esc": "\\n\\t", "uni": "é中𐍈"},
		{"empty": "", "nilv": nil, "nested": []any{float64(1), "two", true}},
	}
	for i := 0; i < 200; i++ {
		// compose shallow / nested rows from the seeds
		var src api.Row
		if i%3 == 0 {
			src = api.Row{}
			for k, v := range seedRows[i%len(seedRows)] {
				src[k] = v
			}
			src["extra"] = i // exercise number boxing
		} else {
			src = seedRows[i%len(seedRows)]
		}
		raw, err := json.Marshal(src)
		if err != nil {
			t.Fatal(err)
		}
		wantRow, wantErr := unmarshalRowReference(string(raw))
		gotRow, gotErr := decodeRowJSON(raw)
		if (wantErr != nil) != (gotErr != nil) {
			t.Fatalf("row %s: error mismatch want %v got %v", raw, wantErr, gotErr)
		}
		if wantErr == nil && !reflect.DeepEqual(apiRowClone(gotRow), apiRowClone(wantRow)) {
			t.Fatalf("row %s:\n want %#v\n got  %#v", raw, wantRow, gotRow)
		}
	}
}

func apiRowClone(r api.Row) api.Row {
	out := make(api.Row, len(r))
	for k, v := range r {
		out[k] = v
	}
	return out
}

// TestDecodeRowJSON_ArenaStringsBondToTheirOwnRow pins the arena
// decoder's ONLY difference from the pre-arena one: all escape-free
// strings of ONE row share that row's private backing buffer, and
// decodes are fully independent — decoding more rows (which append to
// fresh arenas and can force the buffer's backing array to grow across
// rows) must never disturb strings an earlier row returned, and a row's
// strings must survive until long after its decode call ends.
func TestDecodeRowJSON_ArenaStringsBondToTheirOwnRow(t *testing.T) {
	// A WIDE row forces the per-row arena to grow mid-decode (append
	// reallocations), which is exactly the case that could silently
	// corrupt previously-returned strings if the sharing were mishandled.
	var fields []string
	for i := 0; i < 120; i++ {
		fields = append(fields, fmt.Sprintf("\"c%02d\":\"value-%02d\"", i, i))
	}
	first := `{"id":1,` + strings.Join(fields, ",") + `}`
	firstRow, err := decodeRowJSON([]byte(first))
	if err != nil {
		t.Fatal(err)
	}

	// Decode several DIFFERENT rows afterwards; every decode allocates
	// and grows its own arena.
	for j := 0; j < 40; j++ {
		var later []string
		for i := 0; i < 60; i++ {
			later = append(later, fmt.Sprintf("\"d%02d\":\"later-%02d-%02d\"", i, j, i))
		}
		if _, err := decodeRowJSON([]byte(`{"id":2,` + strings.Join(later, ",") + `}`)); err != nil {
			t.Fatal(err)
		}
	}

	// The first row's strings must be byte-exact for every field.
	wantRow, wantErr := unmarshalRowReference(first)
	if wantErr != nil {
		t.Fatal(wantErr)
	}
	if !reflect.DeepEqual(apiRowClone(firstRow), apiRowClone(wantRow)) {
		t.Fatalf("first row's strings corrupted by later decodes:\n want %#v\n got  %#v", wantRow, firstRow)
	}

	// And no cross-row aliasing: the later row's value must not appear
	// where the first row's was.
	if got := firstRow["c00"]; got != "value-00" {
		t.Fatalf("first row's c00 = %v, want value-00", got)
	}
}

package authldap

import "testing"

func TestBEREncodeLength_ShortAndLongForm(t *testing.T) {
	if got := berEncodeLength(10); len(got) != 1 || got[0] != 10 {
		t.Fatalf("short-form length = %x, want [0x0a]", got)
	}
	got := berEncodeLength(300) // needs long form
	if got[0]&0x80 == 0 {
		t.Fatalf("expected long-form length encoding, got %x", got)
	}
	decoded, _ := berDecodeLength(got, 0)
	if decoded != 300 {
		t.Fatalf("berDecodeLength round-trip = %d, want 300", decoded)
	}
}

func TestBEREncodeInteger_RoundTrip(t *testing.T) {
	enc := berEncodeInteger(1000)
	if enc[0] != berTagInteger {
		t.Fatalf("expected integer tag, got %x", enc[0])
	}
}

func TestBEREncodeOctetString(t *testing.T) {
	enc := berEncodeOctetString([]byte("hello"))
	if enc[0] != berTagOctetString {
		t.Fatalf("expected octet string tag, got %x", enc[0])
	}
	length, offset := berDecodeLength(enc, 1)
	if length != 5 {
		t.Fatalf("length = %d, want 5", length)
	}
	if string(enc[offset:offset+length]) != "hello" {
		t.Fatalf("content = %q, want hello", enc[offset:offset+length])
	}
}

func TestBEREncodeFilter_Equality(t *testing.T) {
	enc := berEncodeFilter("(uid=alice)")
	if enc[0] != 0xA3 {
		t.Fatalf("expected equality filter tag 0xA3, got %x", enc[0])
	}
}

func TestBEREncodeFilter_And(t *testing.T) {
	enc := berEncodeFilter("(&(uid=alice)(objectClass=person))")
	if enc[0] != 0xA0 {
		t.Fatalf("expected AND filter tag 0xA0, got %x", enc[0])
	}
}

func TestEscapeFilter(t *testing.T) {
	got := escapeFilter("a*b(c)\\d")
	want := `a\2ab\28c\29\5cd`
	if got != want {
		t.Fatalf("escapeFilter = %q, want %q", got, want)
	}
}

func TestBuildUser_RoleMapping(t *testing.T) {
	p := &Plugin{cfg: Config{RoleMapping: map[string]string{"cn=admins,dc=example,dc=com": "admin"}}}
	user := p.buildUser(map[string]string{
		"dn":       "uid=alice,dc=example,dc=com",
		"uid":      "alice",
		"mail":     "alice@example.com",
		"cn":       "Alice",
		"memberOf": "cn=admins,dc=example,dc=com",
	})
	if user.Username != "alice" || user.Email != "alice@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if len(user.Roles) != 1 || user.Roles[0] != "admin" {
		t.Fatalf("expected role mapping to grant admin, got %v", user.Roles)
	}
}

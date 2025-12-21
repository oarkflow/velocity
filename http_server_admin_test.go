package velocity

import (
	"bytes"
	"context"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mock user storage that authenticates everything as admin for tests
type mockUserStorage struct{}

func (m *mockUserStorage) CreateUser(ctx context.Context, user *User) error { return nil }
func (m *mockUserStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return &User{Username: username, Role: "admin"}, nil
}
func (m *mockUserStorage) GetUserByID(ctx context.Context, id int) (*User, error) { return nil, nil }
func (m *mockUserStorage) UpdateUser(ctx context.Context, user *User) error       { return nil }
func (m *mockUserStorage) DeleteUser(ctx context.Context, id int) error           { return nil }
func (m *mockUserStorage) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	return nil, nil
}
func (m *mockUserStorage) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	return &User{Username: username, Role: "admin"}, nil
}
func (m *mockUserStorage) Authorize(ctx context.Context, principal, tenant, resource, action string) bool {
	return true
}
func (m *mockUserStorage) Close() error { return nil }

func adminToken(t *testing.T) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "admin",
		"role":     "admin",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte("your-secret-key-change-this-in-production"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return s
}

func TestAdminWalHTTPHandlers(t *testing.T) {
	path := t.TempDir()
	db, err := New(path)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	// write and rotate a WAL
	db.wal.SetRotationPolicy(1, "", 2, 0)
	entry := &Entry{Key: []byte("k"), Value: []byte("v"), Timestamp: 1}
	entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
	if err := db.wal.Write(entry); err != nil {
		t.Fatalf("wal write: %v", err)
	}
	if err := db.wal.RotateNow(); err != nil {
		t.Fatalf("wal rotate: %v", err)
	}

	srv := NewHTTPServer(db, "0", &mockUserStorage{})
	// Build request to /admin/wal
	req, _ := http.NewRequest("GET", "/admin/wal", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Test rotate endpoint
	req2, _ := http.NewRequest("POST", "/admin/wal/rotate", nil)
	req2.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp2, err := srv.app.Test(req2)
	if err != nil {
		t.Fatalf("rotate request failed: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("unexpected rotate status: %d", resp2.StatusCode)
	}
}

func TestAdminSSTableRepairHTTP(t *testing.T) {
	tmp := t.TempDir()
	inPath := filepath.Join(tmp, "sst_corrupt2.db")
	entries := []*Entry{
		{Key: []byte("x"), Value: []byte("1"), Timestamp: 1},
		{Key: []byte("y"), Value: []byte("2"), Timestamp: 2},
		{Key: []byte("z"), Value: []byte("3"), Timestamp: 3},
	}
	for _, e := range entries {
		e.checksum = crc32.ChecksumIEEE(append(e.Key, e.Value...))
	}

	// Use the same crypto provider as the DB so the repair can decrypt entries
	dbForSST, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer dbForSST.Close()
	if _, err := NewSSTable(inPath, entries, dbForSST.crypto); err != nil {
		t.Fatalf("create sstable: %v", err)
	}

	// Corrupt the file by overwriting the tail with zeros (simulate partial write)
	f, _ := os.OpenFile(inPath, os.O_RDWR, 0644)
	st, _ := f.Stat()
	if st.Size() > 20 {
		f.Seek(st.Size()-20, 0)
		f.Write(make([]byte, 20))
	}
	f.Close()

	srv := NewHTTPServer(dbForSST, "0", &mockUserStorage{})

	// call repair
	payload := map[string]string{"path": inPath}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/admin/sstable/repair", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	var out struct {
		Recovered int    `json:"recovered"`
		Out       string `json:"out"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Recovered == 0 {
		t.Fatalf("expected some recovered entries")
	}
	if out.Out == "" {
		t.Fatalf("expected out path")
	}
}

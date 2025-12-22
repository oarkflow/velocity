package velocity

import (
	"bytes"
	"context"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestListKeysHTTP(t *testing.T) {
	path := t.TempDir()
	db, err := New(path)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	// put some keys
	db.Put([]byte("a"), []byte("1"))
	db.Put([]byte("b"), []byte("2"))
	db.Put([]byte("c"), []byte("3"))

	srv := NewHTTPServer(db, "0", &mockUserStorage{})
	req, _ := http.NewRequest("GET", "/api/keys?limit=2&offset=1", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	var out struct {
		Total int      `json:"total"`
		Keys  []string `json:"keys"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Total != 3 {
		t.Fatalf("expected total 3 got %d", out.Total)
	}
	if len(out.Keys) != 2 || out.Keys[0] != "b" || out.Keys[1] != "c" {
		t.Fatalf("unexpected keys: %+v", out.Keys)
	}
}

func TestFileThumbnailHTTP(t *testing.T) {
	tmp := t.TempDir()
	db, err := New(tmp)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	// create a small 50x50 red PNG in memory
	img := image.NewRGBA(image.Rect(0, 0, 50, 50))
	for y := 0; y < 50; y++ {
		for x := 0; x < 50; x++ {
			img.Set(x, y, color.RGBA{R: 255, G: 0, B: 0, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}

	meta, err := db.StoreFile("", "red.png", "image/png", buf.Bytes())
	if err != nil {
		t.Fatalf("store file: %v", err)
	}
	// request thumbnail
	srv := NewHTTPServer(db, "0", &mockUserStorage{})
	req, _ := http.NewRequest("GET", "/api/files/"+meta.Key+"/thumbnail", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
		t.Fatalf("unexpected content-type: %s", resp.Header.Get("Content-Type"))
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) == 0 {
		t.Fatalf("empty body")
	}
}

func TestHandleFileUploadStreams(t *testing.T) {
	tmp := t.TempDir()
	db, err := New(tmp)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	srv := NewHTTPServer(db, "0", &mockUserStorage{})

	// build a 1MB payload
	payload := bytes.Repeat([]byte("A"), 1<<20)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", "big.txt")
	if err != nil {
		t.Fatalf("multipart create: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	w.Close()

	req, _ := http.NewRequest("POST", "/api/files", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+adminToken(t))

	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	// read response body to get returned meta
	var out struct {
		Status string       `json:"status"`
		File   FileMetadata `json:"file"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.File.Key == "" {
		t.Fatalf("expected key in response file metadata")
	}
	// verify file exists on disk
	if db.filesDir == "" {
		t.Fatalf("expected db.filesDir to be set")
	}
	path := filepath.Join(db.filesDir, out.File.Key)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file on disk: %v", err)
	}
	_, meta, err := db.GetFile(out.File.Key)
	if err != nil {
		t.Fatalf("expected file stored: %v", err)
	}
	if meta.Filename != "big.txt" {
		t.Fatalf("unexpected filename: %s", meta.Filename)
	}
}
func TestAdminRegenerateThumbnail(t *testing.T) {
	tmp := t.TempDir()
	db, err := New(tmp)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	// create image
	img := image.NewRGBA(image.Rect(0, 0, 50, 50))
	for y := 0; y < 50; y++ {
		for x := 0; x < 50; x++ {
			img.Set(x, y, color.RGBA{R: 0, G: 255, B: 0, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}

	meta, err := db.StoreFile("", "green.png", "image/png", buf.Bytes())
	if err != nil {
		t.Fatalf("store file: %v", err)
	}

	// delete the thumbnail raw key if exists
	_ = db.Delete([]byte(fileThumbPrefix + meta.Key))

	srv := NewHTTPServer(db, "0", &mockUserStorage{})
	req, _ := http.NewRequest("POST", "/admin/thumbnails/"+meta.Key+"/regenerate", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// thumbnail should now exist
	req2, _ := http.NewRequest("GET", "/api/files/"+meta.Key+"/thumbnail", nil)
	req2.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp2, err := srv.app.Test(req2)
	if err != nil {
		t.Fatalf("thumbnail fetch failed: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp2.StatusCode)
	}
}

func TestAdminBulkRegenerateThumbnails(t *testing.T) {
	tmp := t.TempDir()
	db, err := New(tmp)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	// create image
	img := image.NewRGBA(image.Rect(0, 0, 50, 50))
	for y := 0; y < 50; y++ {
		for x := 0; x < 50; x++ {
			img.Set(x, y, color.RGBA{R: 0, G: 0, B: 255, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}

	meta, err := db.StoreFile("", "blue.png", "image/png", buf.Bytes())
	if err != nil {
		t.Fatalf("store file: %v", err)
	}

	// delete
	_ = db.Delete([]byte(fileThumbPrefix + meta.Key))

	srv := NewHTTPServer(db, "0", &mockUserStorage{})
	req, _ := http.NewRequest("POST", "/admin/thumbnails/regenerate", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// thumbnail should now exist
	req2, _ := http.NewRequest("GET", "/api/files/"+meta.Key+"/thumbnail", nil)
	req2.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp2, err := srv.app.Test(req2)
	if err != nil {
		t.Fatalf("thumbnail fetch failed: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp2.StatusCode)
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

func TestAdminStaticServesUI(t *testing.T) {
	// create a server and request the admin index
	path := t.TempDir()
	db, err := New(path)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	srv := NewHTTPServer(db, "0", &mockUserStorage{})
	req, _ := http.NewRequest("GET", "/admin-ui", nil)
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	if !strings.Contains(s, "VelocityDB Admin") {
		t.Fatalf("index did not contain expected heading")
	}
}

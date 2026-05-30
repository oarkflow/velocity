package web

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/s3"
)

func TestS3APIGetObjectMultipleRanges(t *testing.T) {
	db, err := velocity.NewWithConfig(velocity.Config{Path: t.TempDir(), DisableEncryption: true})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer db.Close()

	if _, err := db.StoreObject("bucket/range.txt", "text/plain", "anonymous", []byte("0123456789abcdef"), &velocity.ObjectOptions{Encrypt: false}); err != nil {
		t.Fatalf("StoreObject: %v", err)
	}

	app := fiber.New()
	api := NewS3API(db, s3.NewBucketManager(db, db), s3.NewMultipartManager(db), nil, nil)
	app.Get("/s3/:bucket/*", api.handleGetObject)

	req := httptest.NewRequest(http.MethodGet, "/s3/bucket/range.txt", nil)
	req.Header.Set("Range", "bytes=0-3,8-11")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status=%d want %d", resp.StatusCode, http.StatusPartialContent)
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "multipart/byteranges; boundary=") {
		t.Fatalf("Content-Type=%q", contentType)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	for _, want := range [][]byte{
		[]byte("Content-Range: bytes 0-3/16"),
		[]byte("Content-Range: bytes 8-11/16"),
		[]byte("0123"),
		[]byte("89ab"),
	} {
		if !bytes.Contains(body, want) {
			t.Fatalf("multipart body missing %q:\n%s", want, string(body))
		}
	}
}

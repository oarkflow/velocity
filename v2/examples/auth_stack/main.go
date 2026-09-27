// Command auth_stack demonstrates Velocity v2's auth stack: JWT
// authentication/authorization via auth-jwt (including its refusal to
// start without an explicit signing secret — a deliberate fix for v1's
// critical default-JWT-secret finding), and TOTP second-factor
// verification via auth-mfa (RFC 6238).
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	authjwt "github.com/oarkflow/velocity/v2/plugins/auth-jwt"
	authmfa "github.com/oarkflow/velocity/v2/plugins/auth-mfa"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir, err := os.MkdirTemp("", "velocity-auth-example-*")
	must(err)
	defer os.RemoveAll(dir)

	// auth-jwt refuses to Init without an explicit secret — there is no
	// built-in default, by design (v1's own pentest suite found a
	// default/hardcoded JWT secret that allowed admin token forgery). A
	// real deployment should load this from a secret manager, not a
	// literal in source.
	manifest := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
			{Name: "auth-jwt", Enabled: true, Config: map[string]any{
				"secret": "demo-only-32-byte-minimum-secret!!",
				"issuer": "velocity-example",
			}},
			{Name: "mfa", Enabled: true},
		},
	}

	k := kernel.New(manifest)
	ctx := context.Background()

	all := []api.Plugin{storagelsm.New(), authjwt.New(), authmfa.NewPlugin("storage-lsm")}
	must(k.Boot(ctx, all, manifest.Enabled()))
	defer k.Shutdown(ctx)

	jwtSvc := k.Registry().MustLookup("auth.jwt").(api.AuthProvider)
	issuer := k.Registry().MustLookup("auth.jwt").(api.TokenIssuer)
	mfaSvc := k.Registry().MustLookup("mfa").(api.MFAProvider)

	fmt.Println("=== Issue a JWT for a demo admin, then Authenticate it ===")
	token, err := issuer.IssueToken(ctx, "alice", []string{"admin"}, 5*time.Minute)
	must(err)
	fmt.Printf("issued token: %s...\n", token[:40])

	principal, err := jwtSvc.Authenticate(ctx, token)
	must(err)
	fmt.Printf("Authenticate OK: subject=%s roles=%v\n", principal.Subject, principal.Roles)

	fmt.Println("\n=== Authenticate a tampered token ===")
	tampered := token[:len(token)-4] + "abcd"
	if _, err := jwtSvc.Authenticate(ctx, tampered); err != nil {
		fmt.Printf("tampered token correctly rejected: %v\n", err)
	} else {
		log.Fatal("tampered token was accepted — this should never happen")
	}

	fmt.Println("\n=== Authorize: admin vs non-admin ===")
	adminOK, err := jwtSvc.Authorize(ctx, principal, "delete", "customers/42")
	must(err)
	fmt.Printf("admin role Authorize(delete): %v\n", adminOK)

	userToken, err := issuer.IssueToken(ctx, "bob", []string{"viewer"}, 5*time.Minute)
	must(err)
	userPrincipal, err := jwtSvc.Authenticate(ctx, userToken)
	must(err)
	viewerOK, err := jwtSvc.Authorize(ctx, userPrincipal, "delete", "customers/42")
	must(err)
	fmt.Printf("viewer role Authorize(delete): %v\n", viewerOK)

	fmt.Println("\n=== MFA: enroll alice, then validate a real-time TOTP code ===")
	secret, err := mfaSvc.GenerateSecret(ctx, "alice")
	must(err)
	fmt.Printf("enrolled TOTP secret (base32): %s\n", secret)

	// ValidateCode checks against RFC 6238 codes generated from the
	// secret, exactly as any real authenticator app would. To demonstrate
	// this without a live device, this example implements the same
	// standard RFC 6238 math itself (HMAC-SHA1, 30s step, 6 digits,
	// matching auth-mfa's own defaults) to compute the current valid
	// code from the returned secret.
	code := totp(secret, time.Now())
	fmt.Printf("computed current TOTP code: %s\n", code)

	ok, err := mfaSvc.ValidateCode(ctx, "alice", code)
	must(err)
	fmt.Printf("ValidateCode(correct code): %v\n", ok)

	wrongOK, err := mfaSvc.ValidateCode(ctx, "alice", "000000")
	must(err)
	fmt.Printf("ValidateCode(wrong code):   %v\n", wrongOK)

	fmt.Println("\ndone.")
}

// totp computes an RFC 6238 TOTP code (HMAC-SHA1, 30s period, 6 digits) —
// matching plugins/auth-mfa's default algorithm/period/digits — purely so
// this example can demonstrate ValidateCode accepting a real, correct
// code without a live authenticator app. Not something a real caller
// needs to reimplement; a real client is a standard TOTP app or library.
func totp(secretBase32 string, at time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	must(err)

	counter := uint64(at.Unix() / 30)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	code := binCode % 1000000
	return fmt.Sprintf("%06d", code)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

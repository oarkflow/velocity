package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	ctx := context.Background()
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{Path: dir, DisableEncryption: true, DisableWAL: true})
	check(err)
	defer db.Close()

	mfa := velocity.NewMFAManager(db)
	setup, err := mfa.GenerateTOTPSecret("alice", "alice@example.test")
	check(err)
	token := totp(setup.Secret, time.Now(), setup.Period, setup.Digits)
	totpOK, err := mfa.ValidateTOTP(setup.Secret, token)
	check(err)
	backupOK, err := mfa.ValidateBackupCode("alice", setup.BackupCodes[0])
	check(err)

	rbac := velocity.NewRBACManager(db)
	check(rbac.AddUser(&velocity.User{
		ID: "alice", Username: "alice", Email: "alice@example.test",
		Roles: []string{velocity.RoleAuditor}, ClearanceLevel: string(velocity.DataClassConfidential),
		MFAEnabled: true, Active: true,
		Attributes: map[string]string{"department": "audit"},
	}))
	session, err := rbac.CreateSession("alice", &velocity.AccessContext{IPAddress: "127.0.0.1", UserAgent: "cookbook", MFAVerified: true})
	check(err)
	decision, err := rbac.CheckAccess(ctx, &velocity.AccessRequest{
		UserID: "alice", SessionID: session.SessionID,
		Resource: velocity.ResourceAudit, Action: velocity.ActionRead,
		Context: &velocity.AccessContext{Timestamp: time.Now(), IPAddress: "127.0.0.1", MFAVerified: true},
	})
	check(err)

	iam := velocity.NewIAMPolicyEngine(db)
	check(iam.CreatePolicy(&velocity.IAMPolicy{
		Name: "read-demo-bucket",
		Statements: []velocity.IAMStatement{{
			Sid: "AllowDemoRead", Effect: velocity.IAMEffectAllow,
			Principal: []string{"alice"},
			Action:    []string{"s3:GetObject"},
			Resource:  []string{"arn:velocity:s3:::demo/*"},
			Condition: &velocity.IAMConditionBlock{IpAddress: map[string]string{"aws:SourceIp": "127.0.0.1/32"}},
		}},
	}))
	check(iam.AttachUserPolicy("alice", "read-demo-bucket"))
	iamResult := iam.EvaluateAccess(&velocity.IAMEvalRequest{
		Principal: "alice", Action: "s3:GetObject", Resource: "arn:velocity:s3:::demo/readme.txt",
		Context: map[string]string{"aws:SourceIp": "127.0.0.1"},
	})

	sts := velocity.NewSTSService(db, velocity.WithIAMEngine(iam))
	assumed, err := sts.AssumeRole("alice", &velocity.AssumeRoleInput{
		RoleARN: "arn:velocity:iam::local:role/auditor", RoleSessionName: "cookbook", DurationSeconds: 900,
		PolicyARNs: []string{"read-demo-bucket"},
	})
	check(err)
	stsSession, err := sts.ValidateSessionToken(assumed.Credentials.SessionToken)
	check(err)
	check(sts.RevokeSession(assumed.Credentials.SessionToken))

	fmt.Printf("mfa totp=%t backup=%t\n", totpOK, backupOK)
	fmt.Printf("rbac allowed=%t roles=%v\n", decision.Allowed, decision.RolesEvaluated)
	fmt.Printf("iam allowed=%t policy=%s\n", iamResult.Allowed, iamResult.MatchedPolicy)
	fmt.Printf("sts user=%s access_key_prefix=%s\n", stsSession.UserID, assumed.Credentials.AccessKeyID[:8])
}

func totp(secret string, now time.Time, period int, digits int) string {
	if period <= 0 {
		period = 30
	}
	if digits <= 0 {
		digits = 6
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	check(err)
	counter := uint64(now.Unix() / int64(period))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_identity_security_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

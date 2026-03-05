package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/exec"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/core/share"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

type rotationRecord struct {
	ID          string    `json:"id"`
	Secret      string    `json:"secret"`
	OldValueB64 string    `json:"old_value_b64"`
	NewValueB64 string    `json:"new_value_b64"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type execProfile struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	Prefix     string `json:"prefix,omitempty"`
	Env        string `json:"env,omitempty"`
	EnvPrefix  string `json:"env_prefix,omitempty"`
	AllSecrets bool   `json:"all_secrets,omitempty"`
}

type federationRecord struct {
	Name      string    `json:"name"`
	PeerOrg   string    `json:"peer_org"`
	ServerURL string    `json:"server_url"`
	CreatedAt time.Time `json:"created_at"`
}

func RotateStart(ctx context.Context, cmd *cli.Command) error {
	secretName := strings.TrimSpace(cmd.String("secret"))
	if secretName == "" {
		return fmt.Errorf("secret is required")
	}
	newValue := cmd.String("new-value")
	if strings.TrimSpace(newValue) == "" {
		n, err := randomAlphaNum(40)
		if err != nil {
			return err
		}
		newValue = n
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeSecretRotate); err != nil {
		return err
	}
	mfa := false
	if sess := c.CurrentSession(); sess != nil {
		mfa = sess.MFAVerified
	}
	oldValue, err := c.Secrets.Get(ctx, secretName, c.CurrentIdentityID(), mfa)
	if err != nil {
		return err
	}
	if _, err := c.Secrets.Update(ctx, secretName, []byte(newValue), c.CurrentIdentityID()); err != nil {
		return err
	}

	rec := rotationRecord{
		ID:          fmt.Sprintf("rot-%d", time.Now().UnixNano()),
		Secret:      secretName,
		OldValueB64: base64.StdEncoding.EncodeToString(oldValue),
		NewValueB64: base64.StdEncoding.EncodeToString([]byte(newValue)),
		Status:      "completed",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := saveRotationRecord(rec); err != nil {
		return err
	}
	success("Rotation completed: %s (id=%s)", secretName, rec.ID)
	return nil
}

func RotateStatus(ctx context.Context, cmd *cli.Command) error {
	id := strings.TrimSpace(cmd.String("id"))
	records, err := loadRotationRecords()
	if err != nil {
		return err
	}
	if id == "" {
		return output(cmd, records)
	}
	for _, r := range records {
		if r.ID == id {
			return output(cmd, r)
		}
	}
	return fmt.Errorf("rotation not found: %s", id)
}

func RotateRollback(ctx context.Context, cmd *cli.Command) error {
	id := strings.TrimSpace(cmd.String("id"))
	if id == "" {
		return fmt.Errorf("id is required")
	}
	records, err := loadRotationRecords()
	if err != nil {
		return err
	}
	var rec *rotationRecord
	for i := range records {
		if records[i].ID == id {
			rec = &records[i]
			break
		}
	}
	if rec == nil {
		return fmt.Errorf("rotation not found: %s", id)
	}
	oldValue, err := base64.StdEncoding.DecodeString(rec.OldValueB64)
	if err != nil {
		return err
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeSecretUpdate); err != nil {
		return err
	}
	if _, err := c.Secrets.Update(ctx, rec.Secret, oldValue, c.CurrentIdentityID()); err != nil {
		return err
	}
	rec.Status = "rolled_back"
	rec.UpdatedAt = time.Now().UTC()
	if err := saveRotationRecords(records); err != nil {
		return err
	}
	success("Rotation rolled back: %s (id=%s)", rec.Secret, rec.ID)
	return nil
}

func AuthServiceAccountCreate(ctx context.Context, cmd *cli.Command) error {
	name := strings.TrimSpace(cmd.String("name"))
	if name == "" {
		return fmt.Errorf("name is required")
	}
	description := strings.TrimSpace(cmd.String("description"))
	expiresIn := cmd.Duration("expires-in")
	scopeInputs := cmd.StringSlice("scopes")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeIdentityCreate); err != nil {
		return err
	}
	scopes := make([]types.Scope, 0, len(scopeInputs))
	for _, s := range scopeInputs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		scopes = append(scopes, types.Scope(s))
	}
	ident, creds, err := c.Identity.CreateServiceIdentity(ctx, identity.CreateServiceOptions{
		Name:        name,
		Description: description,
		OwnerID:     c.CurrentIdentityID(),
		Scopes:      scopes,
		ExpiresIn:   expiresIn,
	})
	if err != nil {
		return err
	}
	return output(cmd, map[string]any{
		"id":      ident.ID,
		"name":    ident.Name,
		"api_key": creds.APIKey,
	})
}

func AuthTokenMint(ctx context.Context, cmd *cli.Command) error {
	serviceID := types.ID(strings.TrimSpace(cmd.String("service-id")))
	apiKey := strings.TrimSpace(cmd.String("api-key"))
	if serviceID == "" || apiKey == "" {
		return fmt.Errorf("service-id and api-key are required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeIdentityRead); err != nil {
		return err
	}
	sess, err := c.Identity.AuthenticateService(ctx, serviceID, apiKey)
	if err != nil {
		return err
	}
	return output(cmd, map[string]any{
		"session_id":  sess.ID,
		"identity_id": sess.IdentityID,
		"expires_at":  sess.ExpiresAt.Time(),
		"scopes":      sess.ScopeList,
	})
}

func AuthTokenRevoke(ctx context.Context, cmd *cli.Command) error {
	sid := types.ID(strings.TrimSpace(cmd.String("session-id")))
	if sid == "" {
		return fmt.Errorf("session-id is required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeSessionRevoke); err != nil {
		return err
	}
	if err := c.Identity.RevokeSession(ctx, sid); err != nil {
		return err
	}
	success("Session revoked: %s", sid)
	return nil
}

func DetectLeaks(ctx context.Context, cmd *cli.Command) error {
	root := strings.TrimSpace(cmd.String("path"))
	if root == "" {
		root = "."
	}
	includeValues := cmd.Bool("include-values")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if includeValues {
		if err := c.RequireScope(types.ScopeSecretRead); err != nil {
			return err
		}
	}
	secs, err := c.Secrets.List(ctx, secrets.ListSecretsOptions{})
	if err != nil {
		return err
	}
	patterns := make([]*regexp.Regexp, 0)
	for _, s := range secs {
		if s == nil {
			continue
		}
		if strings.TrimSpace(s.Name) != "" {
			patterns = append(patterns, regexp.MustCompile(regexp.QuoteMeta(s.Name)))
		}
		if includeValues {
			mfa := false
			if sess := c.CurrentSession(); sess != nil {
				mfa = sess.MFAVerified
			}
			if val, gErr := c.Secrets.Get(ctx, s.Name, c.CurrentIdentityID(), mfa); gErr == nil && len(val) > 0 {
				patterns = append(patterns, regexp.MustCompile(regexp.QuoteMeta(string(val))))
			}
		}
	}

	findings := make([]map[string]any, 0)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		b, rErr := os.ReadFile(path)
		if rErr != nil || len(b) == 0 {
			return nil
		}
		content := string(b)
		for _, rx := range patterns {
			if rx.MatchString(content) {
				findings = append(findings, map[string]any{
					"path":    path,
					"pattern": rx.String(),
				})
			}
		}
		return nil
	})
	return output(cmd, map[string]any{
		"path":          root,
		"findings":      findings,
		"finding_count": len(findings),
	})
}

func DetectRuntime(ctx context.Context, cmd *cli.Command) error {
	envFile := strings.TrimSpace(cmd.String("env-file"))
	includeValues := cmd.Bool("include-values")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if includeValues {
		if err := c.RequireScope(types.ScopeSecretRead); err != nil {
			return err
		}
	}
	secs, err := c.Secrets.List(ctx, secrets.ListSecretsOptions{})
	if err != nil {
		return err
	}
	envData := strings.Join(os.Environ(), "\n")
	if envFile != "" {
		b, rErr := os.ReadFile(envFile)
		if rErr != nil {
			return rErr
		}
		envData = string(b)
	}
	findings := make([]map[string]any, 0)
	for _, s := range secs {
		if s == nil {
			continue
		}
		if strings.Contains(envData, s.Name+"=") {
			findings = append(findings, map[string]any{"type": "name", "secret": s.Name})
		}
		if includeValues {
			mfa := false
			if sess := c.CurrentSession(); sess != nil {
				mfa = sess.MFAVerified
			}
			if val, gErr := c.Secrets.Get(ctx, s.Name, c.CurrentIdentityID(), mfa); gErr == nil && len(val) > 0 && strings.Contains(envData, string(val)) {
				findings = append(findings, map[string]any{"type": "value", "secret": s.Name})
			}
		}
	}
	return output(cmd, map[string]any{
		"findings":      findings,
		"finding_count": len(findings),
	})
}

func BackupDrillRun(ctx context.Context, cmd *cli.Command) error {
	id := types.ID(strings.TrimSpace(cmd.String("id")))
	inputPath := strings.TrimSpace(cmd.String("input"))
	if id == "" || inputPath == "" {
		return fmt.Errorf("id and input are required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeBackupVerify); err != nil {
		return err
	}
	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	if len(fileData) < 32 {
		return fmt.Errorf("invalid backup file")
	}
	encryptedData := fileData[32:]
	verify, err := c.Backup.VerifyBackup(ctx, id, encryptedData)
	if err != nil {
		return err
	}
	report := map[string]any{
		"backup_id":    id,
		"input":        inputPath,
		"verified":     verify.Verified,
		"error":        verify.Error,
		"drill_time":   time.Now().UTC(),
		"restore_test": false,
	}
	if err := saveBackupDrillReport(report); err != nil {
		return err
	}
	return output(cmd, report)
}

func BackupDrillReport(ctx context.Context, cmd *cli.Command) error {
	report, err := loadBackupDrillReport()
	if err != nil {
		return err
	}
	return output(cmd, report)
}

func ExecProfileCreate(ctx context.Context, cmd *cli.Command) error {
	name := strings.TrimSpace(cmd.String("name"))
	command := strings.TrimSpace(cmd.String("command"))
	if name == "" || command == "" {
		return fmt.Errorf("name and command are required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeExecRun); err != nil {
		return err
	}
	p := execProfile{
		Name:       name,
		Command:    command,
		Prefix:     strings.TrimSpace(cmd.String("prefix")),
		Env:        strings.TrimSpace(cmd.String("env")),
		EnvPrefix:  strings.TrimSpace(cmd.String("env-prefix")),
		AllSecrets: cmd.Bool("all-secrets"),
	}
	profiles, err := loadExecProfiles()
	if err != nil {
		return err
	}
	replaced := false
	for i := range profiles {
		if profiles[i].Name == name {
			profiles[i] = p
			replaced = true
		}
	}
	if !replaced {
		profiles = append(profiles, p)
	}
	if err := saveExecProfiles(profiles); err != nil {
		return err
	}
	success("Exec profile saved: %s", name)
	return nil
}

func ExecProfileList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeExecRun); err != nil {
		return err
	}
	profiles, err := loadExecProfiles()
	if err != nil {
		return err
	}
	return output(cmd, profiles)
}

func ExecProfileDelete(ctx context.Context, cmd *cli.Command) error {
	name := strings.TrimSpace(cmd.String("name"))
	if name == "" {
		return fmt.Errorf("name is required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeExecRun); err != nil {
		return err
	}
	profiles, err := loadExecProfiles()
	if err != nil {
		return err
	}
	next := make([]execProfile, 0, len(profiles))
	for _, p := range profiles {
		if p.Name != name {
			next = append(next, p)
		}
	}
	if err := saveExecProfiles(next); err != nil {
		return err
	}
	success("Exec profile deleted: %s", name)
	return nil
}

func ExecProfileRun(ctx context.Context, cmd *cli.Command) error {
	name := strings.TrimSpace(cmd.String("name"))
	if name == "" {
		return fmt.Errorf("name is required")
	}
	profiles, err := loadExecProfiles()
	if err != nil {
		return err
	}
	var profile *execProfile
	for i := range profiles {
		if profiles[i].Name == name {
			profile = &profiles[i]
			break
		}
	}
	if profile == nil {
		return fmt.Errorf("profile not found: %s", name)
	}
	command := cmd.String("command")
	if strings.TrimSpace(command) == "" {
		command = profile.Command
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeExecRun); err != nil {
		return err
	}
	mfaVerified := false
	if sess := c.CurrentSession(); sess != nil {
		mfaVerified = sess.MFAVerified
	}
	customEnv := map[string]string{}
	if profile.AllSecrets || profile.Prefix != "" {
		loaded, err := loadBulkSecretsFromVelocity(profile.Prefix, profile.Env)
		if err != nil {
			return err
		}
		if len(loaded) == 0 {
			secretItems, err := c.Secrets.List(ctx, secrets.ListSecretsOptions{
				Prefix:      profile.Prefix,
				Environment: profile.Env,
			})
			if err != nil {
				return err
			}
			for _, item := range secretItems {
				raw, err := c.Secrets.Get(ctx, item.Name, c.CurrentIdentityID(), mfaVerified)
				if err != nil {
					return err
				}
				loaded = append(loaded, namedSecret{Name: item.Name, Value: string(raw)})
			}
		}
		for _, item := range loaded {
			for k, v := range flattenSecretToEnv(secretNameForEnv(item.Name, profile.Prefix), item.Value, profile.EnvPrefix) {
				customEnv[k] = v
			}
		}
	}
	executor := exec.NewExecutor(exec.ExecutorConfig{
		AuditEngine: c.Audit,
		SecretRetriever: func(ctx context.Context, id types.ID) (string, error) {
			val, err := c.Secrets.Get(ctx, string(id), c.CurrentIdentityID(), mfaVerified)
			if err != nil {
				return "", err
			}
			return string(val), nil
		},
	})
	defer executor.Close()
	res, err := executor.Execute(ctx, exec.ExecuteOptions{
		Command: command,
		Args:    cmd.Args().Slice(),
		ActorID: c.CurrentIdentityID(),
		Env:     customEnv,
	})
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("command failed with exit code %d: %s", res.ExitCode, res.Error)
	}
	fmt.Print(res.Stdout)
	return nil
}

func FederationEstablish(ctx context.Context, cmd *cli.Command) error {
	name := strings.TrimSpace(cmd.String("name"))
	peerOrg := strings.TrimSpace(cmd.String("peer-org"))
	serverURL := strings.TrimSpace(cmd.String("server-url"))
	if name == "" || peerOrg == "" || serverURL == "" {
		return fmt.Errorf("name, peer-org and server-url are required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeOrgRead); err != nil {
		return err
	}
	records, err := loadFederations()
	if err != nil {
		return err
	}
	records = append(records, federationRecord{
		Name:      name,
		PeerOrg:   peerOrg,
		ServerURL: serverURL,
		CreatedAt: time.Now().UTC(),
	})
	if err := saveFederations(records); err != nil {
		return err
	}
	success("Federation established: %s", name)
	return nil
}

func FederationShareExternal(ctx context.Context, cmd *cli.Command) error {
	fedName := strings.TrimSpace(cmd.String("federation"))
	shareType := strings.ToLower(strings.TrimSpace(cmd.String("type")))
	resource := strings.TrimSpace(cmd.String("resource"))
	recipientEmail := strings.TrimSpace(cmd.String("recipient-email"))
	expiresIn := cmd.Duration("expires-in")
	if fedName == "" || shareType == "" || resource == "" || recipientEmail == "" {
		return fmt.Errorf("federation, type, resource, recipient-email are required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareExternal); err != nil {
		return err
	}
	if _, err := findFederation(fedName); err != nil {
		return err
	}
	typ, resourceID, err := resolveShareResourceForCreate(ctx, c, shareType, resource)
	if err != nil {
		return err
	}
	shr, token, err := c.Share.CreateExternalShare(ctx, share.ExternalShareOptions{
		Type:           typ,
		ResourceID:     resourceID,
		CreatorID:      c.CurrentIdentityID(),
		RecipientEmail: recipientEmail,
		ExpiresIn:      expiresIn,
	})
	if err != nil {
		return err
	}
	return output(cmd, map[string]any{
		"share_id":      shr.ID,
		"access_token":  token,
		"recipient":     recipientEmail,
		"federation":    fedName,
		"resource_type": typ,
		"resource_id":   resourceID,
	})
}

func randomAlphaNum(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b), nil
}

func execProfilesPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secretr", "exec-profiles.json"), nil
}

func loadExecProfiles() ([]execProfile, error) {
	path, err := execProfilesPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []execProfile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []execProfile
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func saveExecProfiles(p []execProfile) error {
	path, err := execProfilesPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func federationsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secretr", "federations.json"), nil
}

func loadFederations() ([]federationRecord, error) {
	path, err := federationsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []federationRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []federationRecord
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func saveFederations(records []federationRecord) error {
	path, err := federationsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func findFederation(name string) (*federationRecord, error) {
	all, err := loadFederations()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("federation not found: %s", name)
}

func rotationsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secretr", "rotations.json"), nil
}

func loadRotationRecords() ([]rotationRecord, error) {
	path, err := rotationsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []rotationRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []rotationRecord
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func saveRotationRecord(rec rotationRecord) error {
	records, err := loadRotationRecords()
	if err != nil {
		return err
	}
	records = append(records, rec)
	return saveRotationRecords(records)
}

func saveRotationRecords(records []rotationRecord) error {
	path, err := rotationsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func drillReportPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secretr", "drills", "latest.json"), nil
}

func saveBackupDrillReport(report map[string]any) error {
	path, err := drillReportPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func loadBackupDrillReport() (map[string]any, error) {
	path, err := drillReportPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report map[string]any
	if err := json.Unmarshal(b, &report); err != nil {
		return nil, err
	}
	return report, nil
}

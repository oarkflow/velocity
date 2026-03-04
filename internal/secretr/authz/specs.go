package authz

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode"

	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

type FlagClass string

const (
	FlagClassSensitive        FlagClass = "sensitive"
	FlagClassResourceSelector FlagClass = "resource_selector"
	FlagClassControl          FlagClass = "control"
	FlagClassOutput           FlagClass = "output"
)

type FlagAuthSpec struct {
	Name           string
	Class          FlagClass
	RequiredScopes []types.Scope
	RequireACL     bool
	SpecMissing    bool
}

type ArgAuthSpec struct {
	Position       int
	Name           string
	RequiredScopes []types.Scope
	RequireACL     bool
	SpecMissing    bool
}

type CommandAuthSpec struct {
	Path           string
	RequiredScopes []types.Scope
	ResourceType   string
	RequireACL     bool
	Flags          map[string]FlagAuthSpec
	Args           []ArgAuthSpec
	AllowUnauth    bool
	SpecMissing    bool
}

type APIRouteAuthSpec struct {
	Method         string
	Pattern        string
	RequiredScopes []types.Scope
	ResourceType   string
	RequireACL     bool
	AllowUnauth    bool
}

type CommandDispatchAuthSpec struct {
	Path           string
	RequiredScopes []types.Scope
	ResourceType   string
	RequireACL     bool
	AllowUnauth    bool
}

type commandScopeManifestEntry struct {
	Path   string   `json:"path"`
	Scopes []string `json:"scopes"`
}

type commandSurfaceManifestEntry struct {
	Path  string             `json:"path"`
	Flags []flagSurfaceEntry `json:"flags"`
	Args  []argSurfaceEntry  `json:"args"`
}

type flagSurfaceEntry struct {
	Name       string `json:"name"`
	Class      string `json:"class"`
	RequireACL bool   `json:"require_acl"`
}

type argSurfaceEntry struct {
	Position   int    `json:"position"`
	Name       string `json:"name"`
	RequireACL bool   `json:"require_acl"`
}

//go:embed command_scope_manifest.json
var commandScopeManifestJSON []byte

//go:embed command_surface_manifest.json
var commandSurfaceManifestJSON []byte

var commandScopeManifest = loadCommandScopeManifest()
var commandSurfaceManifest = loadCommandSurfaceManifest()

func BuildCLIAuthSpecs(root *cli.Command, scopeResolver func(path string) []types.Scope) map[string]CommandAuthSpec {
	out := make(map[string]CommandAuthSpec)
	walkCLISpec(root, "", out, scopeResolver)
	return out
}

func MissingCLICommandScopes(root *cli.Command, scopeResolver func(path string) []types.Scope) []string {
	out := make([]string, 0)
	var walk func(cmd *cli.Command, prefix string)
	walk = func(cmd *cli.Command, prefix string) {
		if cmd == nil {
			return
		}
		for _, sub := range cmd.Commands {
			name := strings.TrimSpace(sub.Name)
			if name == "" || name == "help" || name == "h" {
				continue
			}
			path := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
			if _, ok := resolveCommandScopesStrict(path, scopeResolver); !ok {
				out = append(out, path)
			}
			walk(sub, path)
		}
	}
	walk(root, "")
	sort.Strings(out)
	return out
}

func MissingCLICommandSurface(root *cli.Command) []string {
	out := make([]string, 0)
	var walk func(cmd *cli.Command, prefix string)
	walk = func(cmd *cli.Command, prefix string) {
		if cmd == nil {
			return
		}
		for _, sub := range cmd.Commands {
			name := strings.TrimSpace(sub.Name)
			if name == "" || name == "help" || name == "h" {
				continue
			}
			path := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
			surface, ok := commandSurfaceManifest[path]
			if !ok {
				out = append(out, path)
				walk(sub, path)
				continue
			}
			flagSet := map[string]struct{}{}
			for _, f := range surface.Flags {
				flagSet[strings.TrimSpace(f.Name)] = struct{}{}
			}
			for _, flg := range sub.Flags {
				names := flg.Names()
				if len(names) == 0 {
					continue
				}
				if _, exists := flagSet[names[0]]; !exists {
					out = append(out, path+"#flag:"+names[0])
				}
			}
			expectedArgs := inferArgsFromUsage(sub.ArgsUsage)
			argSet := map[int]struct{}{}
			for _, a := range surface.Args {
				argSet[a.Position] = struct{}{}
			}
			for _, a := range expectedArgs {
				if _, ok := argSet[a.Position]; ok {
					continue
				}
				if _, ok := argSet[-1]; ok {
					continue
				}
				out = append(out, fmt.Sprintf("%s#arg:%d", path, a.Position))
			}
			walk(sub, path)
		}
	}
	walk(root, "")
	sort.Strings(out)
	return out
}

func walkCLISpec(cmd *cli.Command, prefix string, out map[string]CommandAuthSpec, scopeResolver func(path string) []types.Scope) {
	if cmd == nil {
		return
	}
	for _, sub := range cmd.Commands {
		name := strings.TrimSpace(sub.Name)
		if name == "" || name == "help" || name == "h" {
			continue
		}
		path := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
		required, resolved := resolveCommandScopesStrict(path, scopeResolver)
		allowUnauth := path == "auth" || strings.HasPrefix(path, "auth ")
		surface, hasSurface := commandSurfaceManifest[path]
		specMissing := (!resolved || !hasSurface) && !allowUnauth

		flagSpecs := make(map[string]FlagAuthSpec)
		surfaceFlags := map[string]flagSurfaceEntry{}
		if hasSurface {
			for _, f := range surface.Flags {
				surfaceFlags[strings.TrimSpace(f.Name)] = f
			}
		}
		for _, flg := range sub.Flags {
			names := flg.Names()
			if len(names) == 0 {
				continue
			}
			primary := names[0]
			sf, ok := surfaceFlags[primary]
			class := classifyFlag(primary)
			requireACL := class == FlagClassResourceSelector
			flagSpecMissing := specMissing || !ok
			if ok {
				class = parseFlagClass(sf.Class)
				requireACL = sf.RequireACL
			}
			flagSpecs[primary] = FlagAuthSpec{
				Name:           primary,
				Class:          class,
				RequiredScopes: required,
				RequireACL:     requireACL,
				SpecMissing:    flagSpecMissing,
			}
		}

		argSpecs := buildArgSpecs(sub, required, specMissing, hasSurface, surface.Args)
		out[path] = CommandAuthSpec{
			Path:           path,
			RequiredScopes: required,
			ResourceType:   inferResourceType(path),
			RequireACL:     requiresACL(path),
			Flags:          flagSpecs,
			Args:           argSpecs,
			AllowUnauth:    allowUnauth,
			SpecMissing:    specMissing,
		}

		walkCLISpec(sub, path, out, scopeResolver)
	}
}

func classifyFlag(name string) FlagClass {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "format" || n == "quiet" || n == "debug" || n == "yes" {
		return FlagClassOutput
	}
	if strings.Contains(n, "password") || strings.Contains(n, "token") || strings.Contains(n, "secret") || strings.Contains(n, "key") || strings.Contains(n, "signer") {
		return FlagClassSensitive
	}
	if strings.Contains(n, "id") || strings.Contains(n, "name") || strings.Contains(n, "path") || strings.Contains(n, "file") || strings.Contains(n, "folder") || strings.Contains(n, "resource") || strings.Contains(n, "org") {
		return FlagClassResourceSelector
	}
	return FlagClassControl
}

func parseFlagClass(raw string) FlagClass {
	switch strings.TrimSpace(raw) {
	case string(FlagClassSensitive):
		return FlagClassSensitive
	case string(FlagClassResourceSelector):
		return FlagClassResourceSelector
	case string(FlagClassOutput):
		return FlagClassOutput
	case string(FlagClassControl):
		fallthrough
	default:
		return FlagClassControl
	}
}

func inferResourceType(path string) string {
	first := path
	if idx := strings.Index(first, " "); idx > 0 {
		first = first[:idx]
	}
	switch normalizeDomain(first) {
	case "secret":
		return "secret"
	case "file", "object", "data", "import", "export":
		return "file"
	case "folder":
		return "folder"
	case "key":
		return "key"
	case "identity", "device", "session", "org", "role", "policy", "access", "share", "backup", "pipeline", "audit", "admin", "incident", "envelope", "ssh", "compliance", "dlp":
		return normalizeDomain(first)
	default:
		return ""
	}
}

func requiresACL(path string) bool {
	rt := inferResourceType(path)
	return rt != "" && rt != "auth" && rt != "admin"
}

func ResolveAPIRouteSpec(method, path string, specs []APIRouteAuthSpec) (APIRouteAuthSpec, bool) {
	for _, s := range specs {
		if s.Method != method {
			continue
		}
		if strings.HasSuffix(s.Pattern, "/") {
			if strings.HasPrefix(path, s.Pattern) {
				return s, true
			}
			continue
		}
		if path == s.Pattern {
			return s, true
		}
	}
	return APIRouteAuthSpec{}, false
}

func CommandPathFromDispatchURL(path string) string {
	raw := strings.TrimSpace(strings.TrimPrefix(path, "/api/v1/commands/"))
	raw = strings.Trim(raw, "/")
	if raw == "" {
		return ""
	}
	return strings.ReplaceAll(raw, "/", " ")
}

func DispatchPathFromCommandPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "/")
	if path == "" {
		return "/api/v1/commands/"
	}
	return "/api/v1/commands/" + strings.ReplaceAll(path, " ", "/")
}

func ReadAndRestoreJSONBody(r *http.Request) map[string]any {
	if r == nil || r.Body == nil {
		return nil
	}
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return payload
}

func ResolveCommandDispatchAuth(path string) (CommandDispatchAuthSpec, error) {
	cmdPath := strings.TrimSpace(path)
	if cmdPath == "" {
		return CommandDispatchAuthSpec{}, fmt.Errorf("empty command path")
	}
	if cmdPath == "auth" || cmdPath == "auth login" {
		return CommandDispatchAuthSpec{
			Path:        cmdPath,
			AllowUnauth: true,
		}, nil
	}

	scopes, ok := resolveCommandScopesStrict(cmdPath, nil)
	if !ok {
		return CommandDispatchAuthSpec{}, fmt.Errorf("command auth spec missing: %s", cmdPath)
	}
	return CommandDispatchAuthSpec{
		Path:           cmdPath,
		RequiredScopes: scopes,
		ResourceType:   inferResourceType(cmdPath),
		RequireACL:     requiresACL(cmdPath),
		AllowUnauth:    cmdPath == "auth" || strings.HasPrefix(cmdPath, "auth "),
	}, nil
}

func NormalizeCommandPath(fullName string) string {
	path := strings.TrimSpace(fullName)
	path = strings.TrimPrefix(path, "secretr")
	path = strings.TrimSpace(path)
	return path
}

func ResolveCLICommandSpec(cmd *cli.Command, specs map[string]CommandAuthSpec) (CommandAuthSpec, error) {
	path := NormalizeCommandPath(cmd.FullName())
	if path == "" {
		return CommandAuthSpec{}, fmt.Errorf("root command")
	}
	spec, ok := specs[path]
	if !ok {
		return CommandAuthSpec{}, fmt.Errorf("command spec missing: %s", path)
	}
	return spec, nil
}

func buildArgSpecs(cmd *cli.Command, required []types.Scope, specMissing bool, hasSurface bool, surfaceArgs []argSurfaceEntry) []ArgAuthSpec {
	if hasSurface {
		specs := make([]ArgAuthSpec, 0, len(surfaceArgs))
		for _, a := range surfaceArgs {
			specs = append(specs, ArgAuthSpec{
				Position:       a.Position,
				Name:           a.Name,
				RequiredScopes: required,
				RequireACL:     a.RequireACL,
				SpecMissing:    specMissing,
			})
		}
		return specs
	}
	inferred := inferArgsFromUsage(cmd.ArgsUsage)
	if len(inferred) == 0 {
		return []ArgAuthSpec{{Position: -1, Name: "*", RequiredScopes: required, RequireACL: true, SpecMissing: specMissing}}
	}
	specs := make([]ArgAuthSpec, 0, len(inferred))
	for _, a := range inferred {
		specs = append(specs, ArgAuthSpec{
			Position:       a.Position,
			Name:           a.Name,
			RequiredScopes: required,
			RequireACL:     true,
			SpecMissing:    specMissing,
		})
	}
	return specs
}

func inferArgsFromUsage(argsUsage string) []argSurfaceEntry {
	usage := strings.TrimSpace(argsUsage)
	if usage == "" {
		return nil
	}

	tokens := strings.Fields(usage)
	out := make([]argSurfaceEntry, 0, len(tokens))
	position := 0
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		hasMarker := strings.Contains(tok, "<") || strings.Contains(tok, "[")
		if !hasMarker {
			continue
		}
		name := normalizeArgName(tok)
		if strings.Contains(tok, "...") {
			out = append(out, argSurfaceEntry{Position: -1, Name: name, RequireACL: true})
			continue
		}
		out = append(out, argSurfaceEntry{Position: position, Name: name, RequireACL: true})
		position++
	}
	return out
}

func normalizeArgName(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-', r == '*':
			return r
		default:
			return -1
		}
	}, strings.ToLower(s))
	if out == "" {
		return "arg"
	}
	return out
}

func resolveCommandScopesStrict(path string, scopeResolver func(path string) []types.Scope) ([]types.Scope, bool) {
	if scopeResolver != nil {
		if scopes := scopeResolver(path); len(scopes) > 0 {
			return scopes, true
		}
	}
	if scopes, ok := commandScopeManifest[path]; ok {
		return scopes, true
	}
	if path == "auth" || strings.HasPrefix(path, "auth ") {
		return nil, true
	}
	return nil, false
}

func loadCommandScopeManifest() map[string][]types.Scope {
	entries := make([]commandScopeManifestEntry, 0)
	if err := json.Unmarshal(commandScopeManifestJSON, &entries); err != nil {
		return map[string][]types.Scope{}
	}
	out := make(map[string][]types.Scope, len(entries))
	for _, e := range entries {
		path := strings.TrimSpace(e.Path)
		if path == "" {
			continue
		}
		scopes := make([]types.Scope, 0, len(e.Scopes))
		for _, raw := range e.Scopes {
			s := types.Scope(strings.TrimSpace(raw))
			if s == "" {
				continue
			}
			scopes = append(scopes, s)
		}
		out[path] = scopes
	}
	return out
}

func loadCommandSurfaceManifest() map[string]commandSurfaceManifestEntry {
	entries := make([]commandSurfaceManifestEntry, 0)
	if err := json.Unmarshal(commandSurfaceManifestJSON, &entries); err != nil {
		return map[string]commandSurfaceManifestEntry{}
	}
	out := make(map[string]commandSurfaceManifestEntry, len(entries))
	for _, e := range entries {
		path := strings.TrimSpace(e.Path)
		if path == "" {
			continue
		}
		out[path] = e
	}
	return out
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	switch d {
	case "secrets":
		return "secret"
	case "files", "object", "objects", "data", "import", "export":
		return "file"
	case "orgs", "organization", "organizations":
		return "org"
	case "keys":
		return "key"
	case "roles":
		return "role"
	case "policies":
		return "policy"
	case "shares":
		return "share"
	case "alerts", "monitoring":
		return "audit"
	case "pipelines", "automation":
		return "pipeline"
	}
	return d
}

func normalizeAction(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	switch a {
	case "ls", "list", "search":
		return "list"
	case "get", "show", "view", "status", "info":
		return "read"
	case "new", "add", "init", "create", "declare", "enroll", "generate", "upload":
		return "create"
	case "set", "edit", "patch", "update", "rotate", "trust", "bind", "assign", "inject", "enforce", "rules", "policy":
		return "update"
	case "remove", "rm", "del", "delete", "destroy", "revoke", "shred":
		return "delete"
	case "download":
		return "download"
	case "auth", "login":
		return "auth"
	case "export":
		return "export"
	case "import":
		return "import"
	case "verify":
		return "verify"
	case "restore":
		return "restore"
	case "schedule":
		return "schedule"
	case "approve":
		return "approve"
	case "freeze":
		return "freeze"
	case "open":
		return "open"
	case "connect":
		return "connect"
	case "run", "exec":
		return "run"
	}
	return a
}

func isKnownScope(scope types.Scope) bool {
	_, ok := knownScopes[scope]
	return ok
}

var knownScopes = map[types.Scope]struct{}{
	types.ScopeAuthLogin: {}, types.ScopeAuthLogout: {}, types.ScopeAuthRotate: {},
	types.ScopeIdentityCreate: {}, types.ScopeIdentityRead: {}, types.ScopeIdentityUpdate: {}, types.ScopeIdentityDelete: {}, types.ScopeIdentityRecover: {}, types.ScopeIdentityManage: {}, types.ScopeIdentityService: {}, types.ScopeIdentityProvenance: {},
	types.ScopeDeviceEnroll: {}, types.ScopeDeviceRead: {}, types.ScopeDeviceRevoke: {}, types.ScopeDeviceAttest: {}, types.ScopeDeviceTrust: {}, types.ScopeDeviceFingerprint: {},
	types.ScopeSessionCreate: {}, types.ScopeSessionRead: {}, types.ScopeSessionRevoke: {}, types.ScopeSessionOffline: {},
	types.ScopeKeyGenerate: {}, types.ScopeKeyRead: {}, types.ScopeKeyRotate: {}, types.ScopeKeyDestroy: {}, types.ScopeKeyExport: {}, types.ScopeKeyImport: {}, types.ScopeKeyVersion: {}, types.ScopeKeyRecovery: {}, types.ScopeKeyEscrow: {}, types.ScopeKeyHardware: {},
	types.ScopeSecretCreate: {}, types.ScopeSecretRead: {}, types.ScopeSecretUpdate: {}, types.ScopeSecretDelete: {}, types.ScopeSecretList: {}, types.ScopeSecretHistory: {}, types.ScopeSecretRotate: {}, types.ScopeSecretShare: {}, types.ScopeSecretExport: {},
	types.ScopeFileUpload: {}, types.ScopeFileDownload: {}, types.ScopeFileList: {}, types.ScopeFileDelete: {}, types.ScopeFileSeal: {}, types.ScopeFileUnseal: {}, types.ScopeFileShred: {}, types.ScopeFileShare: {}, types.ScopeFileExport: {},
	types.ScopeAccessGrant: {}, types.ScopeAccessRevoke: {}, types.ScopeAccessDelegate: {}, types.ScopeAccessRead: {}, types.ScopeAccessApprove: {}, types.ScopeAccessEmergency: {}, types.ScopeAccessInherit: {}, types.ScopeAccessRequest: {},
	types.ScopeRoleCreate: {}, types.ScopeRoleRead: {}, types.ScopeRoleUpdate: {}, types.ScopeRoleDelete: {}, types.ScopeRoleAssign: {},
	types.ScopePolicyCreate: {}, types.ScopePolicyRead: {}, types.ScopePolicyUpdate: {}, types.ScopePolicyDelete: {}, types.ScopePolicyBind: {}, types.ScopePolicySimulate: {}, types.ScopePolicyFreeze: {}, types.ScopePolicySign: {},
	types.ScopeAuditRead: {}, types.ScopeAuditQuery: {}, types.ScopeAuditExport: {}, types.ScopeAuditVerify: {}, types.ScopeAuditRedact: {},
	types.ScopeShareCreate: {}, types.ScopeShareRead: {}, types.ScopeShareRevoke: {}, types.ScopeShareAccept: {}, types.ScopeShareExport: {}, types.ScopeShareReshare: {}, types.ScopeShareExternal: {},
	types.ScopeBackupCreate: {}, types.ScopeBackupRestore: {}, types.ScopeBackupVerify: {}, types.ScopeBackupSchedule: {}, types.ScopeBackupQuorum: {},
	types.ScopeOrgCreate: {}, types.ScopeOrgRead: {}, types.ScopeOrgUpdate: {}, types.ScopeOrgDelete: {}, types.ScopeOrgInvite: {}, types.ScopeOrgRevoke: {}, types.ScopeOrgTeams: {}, types.ScopeOrgEnv: {}, types.ScopeOrgCompliance: {}, types.ScopeOrgAuditor: {}, types.ScopeOrgOnboard: {}, types.ScopeOrgOffboard: {}, types.ScopeOrgLegalHold: {},
	types.ScopeIncidentDeclare: {}, types.ScopeIncidentFreeze: {}, types.ScopeIncidentRotate: {}, types.ScopeIncidentExport: {}, types.ScopeIncidentMonitor: {}, types.ScopeIncidentTimeline: {},
	types.ScopeEnvelopeCreate: {}, types.ScopeEnvelopeOpen: {}, types.ScopeEnvelopeVerify: {},
	types.ScopeAuditorRead: {}, types.ScopeAuditorExport: {},
	types.ScopeVendorAccess: {}, types.ScopeVendorLimited: {}, types.ScopeVendorManage: {},
	types.ScopeSSHProfile: {}, types.ScopeSSHConnect: {}, types.ScopeSSHExecute: {}, types.ScopeSSHManage: {},
	types.ScopePipelineCreate: {}, types.ScopePipelineAuth: {}, types.ScopePipelineInject: {}, types.ScopePipelineEnforce: {},
	types.ScopeExecRun:      {},
	types.ScopeTransferInit: {}, types.ScopeTransferApprove: {}, types.ScopeTransferExecute: {},
	types.ScopeAdminAll: {}, types.ScopeAdminUsers: {}, types.ScopeAdminSystem: {}, types.ScopeAdminSecurity: {},
	types.ScopeComplianceReport: {}, types.ScopeCompliancePolicy: {}, types.ScopeDLPScan: {}, types.ScopeDLPRules: {}, types.ScopeAutomationManage: {},
}

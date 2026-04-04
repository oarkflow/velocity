package authz

import (
	"fmt"
	"net/http"
	"strings"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// ResourceResolver centralizes resource and usage-context extraction for CLI/API authz requests.
type ResourceResolver interface {
	ResolveCLI(cmd *cli.Command, session *types.Session, path string, spec CommandAuthSpec) (resourceType string, resourceID string, usage licclient.UsageContext, metadata map[string]any)
	ResolveCLIFlag(cmd *cli.Command, session *types.Session, path string, spec CommandAuthSpec, flagNames []string, flagSpec FlagAuthSpec) (resourceID string, usage licclient.UsageContext, metadata map[string]any)
	ResolveCLIArg(session *types.Session, path string, spec CommandAuthSpec, position int, value string, argSpec ArgAuthSpec) (resourceID string, usage licclient.UsageContext, metadata map[string]any)
	ResolveAPI(r *http.Request, session *types.Session, spec APIRouteAuthSpec) (resourceType string, resourceID string, usage licclient.UsageContext, metadata map[string]any)
}

type DefaultResourceResolver struct{}

func NewDefaultResourceResolver() *DefaultResourceResolver {
	return &DefaultResourceResolver{}
}

func (r *DefaultResourceResolver) ResolveCLI(cmd *cli.Command, session *types.Session, path string, spec CommandAuthSpec) (string, string, licclient.UsageContext, map[string]any) {
	resourceID := resolveResourceIDFromCLIFlags(cmd)
	args := cliArgsSlice(cmd)
	if resourceID == "" && len(args) > 0 {
		resourceID = strings.TrimSpace(args[0])
	}
	if resourceID == "" && spec.RequireACL && !isCollectionScopeRequest(spec.RequiredScopes) {
		resourceID = "*"
	}
	metadata := map[string]any{
		"command":         path,
		"mfa_verified":    session != nil && session.MFAVerified,
		"access_approved": true,
	}
	if session != nil && session.DeviceID != "" {
		metadata["device_id"] = session.DeviceID
	}
	return spec.ResourceType, resourceID, usageContextFromSession(session, resourceID), metadata
}

func (r *DefaultResourceResolver) ResolveCLIFlag(cmd *cli.Command, session *types.Session, path string, spec CommandAuthSpec, flagNames []string, flagSpec FlagAuthSpec) (string, licclient.UsageContext, map[string]any) {
	resourceID := resolveSingleFlagValue(cmd, flagNames)
	metadata := map[string]any{
		"command":       path,
		"flag":          strings.Join(flagNames, ","),
		"flag_class":    string(flagSpec.Class),
		"resource_type": spec.ResourceType,
	}
	return resourceID, usageContextFromSession(session, resourceID), metadata
}

func (r *DefaultResourceResolver) ResolveCLIArg(session *types.Session, path string, spec CommandAuthSpec, position int, value string, argSpec ArgAuthSpec) (string, licclient.UsageContext, map[string]any) {
	resourceID := strings.TrimSpace(value)
	metadata := map[string]any{
		"command":       path,
		"arg_position":  position,
		"arg_name":      argSpec.Name,
		"resource_type": spec.ResourceType,
	}
	return resourceID, usageContextFromSession(session, resourceID), metadata
}

func (r *DefaultResourceResolver) ResolveAPI(req *http.Request, session *types.Session, spec APIRouteAuthSpec) (string, string, licclient.UsageContext, map[string]any) {
	resourceID := resolveAPIResourceIDForResolver(req, spec)
	if resourceID == "" && spec.RequireACL && !isCollectionScopeRequest(spec.RequiredScopes) {
		resourceID = "*"
	}
	metadata := map[string]any{
		"method":          req.Method,
		"path":            req.URL.Path,
		"client_ip":       getClientIPFromRequest(req),
		"mfa_verified":    session != nil && session.MFAVerified,
		"access_approved": strings.EqualFold(req.Header.Get("X-Access-Approved"), "true"),
	}
	if session != nil && session.DeviceID != "" {
		metadata["device_id"] = session.DeviceID
	}
	return spec.ResourceType, resourceID, usageContextFromSession(session, resourceID), metadata
}

func resolveResourceIDFromCLIFlags(cmd *cli.Command) string {
	if cmd == nil {
		return ""
	}
	candidates := []string{"id", "name", "resource-id", "resource", "file", "path", "key", "org-id"}
	for _, c := range candidates {
		if !cliIsSet(cmd, c) {
			continue
		}
		if v := strings.TrimSpace(cliString(cmd, c)); v != "" {
			return v
		}
	}
	return ""
}

func resolveSingleFlagValue(cmd *cli.Command, names []string) string {
	if cmd == nil {
		return ""
	}
	for _, name := range names {
		if v := strings.TrimSpace(cliString(cmd, name)); v != "" {
			return v
		}
	}
	return ""
}

func cliArgsSlice(cmd *cli.Command) []string {
	if cmd == nil {
		return nil
	}
	defer func() {
		_ = recover()
	}()
	return cmd.Args().Slice()
}

func cliString(cmd *cli.Command, name string) string {
	if cmd == nil {
		return ""
	}
	defer func() {
		_ = recover()
	}()
	return cmd.String(name)
}

func cliIsSet(cmd *cli.Command, name string) bool {
	if cmd == nil {
		return false
	}
	defer func() {
		_ = recover()
	}()
	return cmd.IsSet(name)
}

func usageContextFromSession(session *types.Session, subject string) licclient.UsageContext {
	ctx := licclient.UsageContext{
		SubjectType: licclient.SubjectTypeUser,
		SubjectID:   "",
		Amount:      1,
	}
	if session != nil {
		ctx.SubjectID = string(session.IdentityID)
		if session.DeviceID != "" {
			ctx.SubjectType = licclient.SubjectTypeDevice
			ctx.SubjectID = string(session.DeviceID)
		}
	}
	if subject != "" {
		ctx.SubjectType = licclient.SubjectTypeStorage
		ctx.SubjectID = subject
	}
	return ctx
}

func resolveAPIResourceIDForResolver(r *http.Request, spec APIRouteAuthSpec) string {
	if r == nil {
		return ""
	}
	path := strings.TrimSpace(r.URL.Path)
	if strings.HasPrefix(path, "/api/v1/commands/") {
		cmdPath := CommandPathFromDispatchURL(path)
		if cmdPath != "" {
			return cmdPath
		}
	}
	for _, key := range []string{"id", "name", "resource_id", "resource", "secret_id", "file_id"} {
		if v := strings.TrimSpace(r.URL.Query().Get(key)); v != "" {
			return v
		}
	}
	payload := ReadAndRestoreJSONBody(r)
	for _, key := range []string{"id", "name", "resource_id", "resource", "secret_id", "file_id"} {
		if v := payloadString(payload, key); v != "" {
			return v
		}
	}
	if spec.Pattern != "" && strings.HasSuffix(spec.Pattern, "/") {
		trimmedPath := strings.Trim(path, "/")
		trimmedPattern := strings.Trim(spec.Pattern, "/")
		if strings.HasPrefix(trimmedPath, trimmedPattern) {
			rest := strings.TrimPrefix(trimmedPath, trimmedPattern)
			rest = strings.TrimPrefix(rest, "/")
			if rest != "" {
				return rest
			}
		}
	}
	if pathID := resolveAPIResourceIDFromPath(path); pathID != "" {
		return pathID
	}
	return ""
}

func getClientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return strings.Split(ip, ",")[0]
	}
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}
	if r.RemoteAddr == "" {
		return ""
	}
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ":")
}

func payloadString(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	raw, ok := payload[key]
	if !ok || raw == nil {
		return ""
	}
	if s, ok := raw.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprint(raw))
}

func resolveAPIResourceIDFromPath(path string) string {
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return ""
	}
	resource := parts[3]
	if resource == "" {
		return ""
	}
	for _, reserved := range []string{"dashboard", "events", "stream", "rules", "notifiers", "auth", "commands"} {
		if resource == reserved {
			return ""
		}
	}
	return resource
}

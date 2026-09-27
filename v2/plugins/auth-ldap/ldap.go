// Package authldap implements the auth-ldap plugin: a hand-rolled BER/
// ASN.1 LDAP wire-protocol client (bind/search/unbind over TCP/TLS),
// ported from v1's ldap_provider.go, adapted from a *DB-coupled provider
// to a standalone api.AuthProvider plugin.
package authldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

const (
	PluginName  = "auth-ldap"
	ServiceName = "auth.ldap"
)

// BER-TLV tag constants.
const (
	berTagSequence    = 0x30
	berTagSet         = 0x31
	berTagInteger     = 0x02
	berTagOctetString = 0x04
	berTagEnumerated  = 0x0A
	berTagBoolean     = 0x01
	berTagContextZero = 0x80
)

// LDAP protocol constants.
const (
	ldapAppBindRequest    = 0x60
	ldapAppSearchRequest  = 0x63
	ldapAppSearchEntry    = 0x64
	ldapAppSearchDone     = 0x65
	ldapAppUnbindRequest  = 0x42
	ldapResultSuccess     = 0
	ldapScopeWholeSubtree = 2
	ldapDerefNever        = 0
)

// Config is the auth-ldap plugin's manifest configuration.
type Config struct {
	ServerURL    string
	BindDN       string
	BindPassword string
	BaseDN       string
	UserFilter   string
	GroupFilter  string
	TLS          bool
	TLSInsecure  bool
	RoleMapping  map[string]string
	Timeout      time.Duration
}

// Credential is what callers pass to Authenticate.
type Credential struct {
	Username string
	Password string
}

// User is an LDAP-resolved identity.
type User struct {
	DN       string
	Username string
	Email    string
	Name     string
	Groups   []string
	Roles    []string
	Attrs    map[string]string
}

// Plugin implements api.Plugin and api.AuthProvider.
type Plugin struct {
	mu      sync.RWMutex
	cfg     Config
	events  api.EventBus
	log     api.Logger
	started bool
}

func New() *Plugin { return &Plugin{} }

var (
	_ api.Plugin       = (*Plugin)(nil)
	_ api.AuthProvider = (*Plugin)(nil)
)

func (p *Plugin) Name() string           { return PluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	c := k.Config().Scoped(PluginName)
	cfg := Config{
		ServerURL:    c.String("server_url", ""),
		BindDN:       c.String("bind_dn", ""),
		BindPassword: c.String("bind_password", ""),
		BaseDN:       c.String("base_dn", ""),
		UserFilter:   c.String("user_filter", "(uid=%s)"),
		GroupFilter:  c.String("group_filter", "(member=%s)"),
		TLS:          c.Bool("tls", false),
		TLSInsecure:  c.Bool("tls_insecure", false),
		Timeout:      c.Duration("timeout", 10*time.Second),
	}
	if cfg.ServerURL == "" || cfg.BaseDN == "" {
		return fmt.Errorf("auth-ldap: server_url and base_dn are required config keys")
	}
	if rm, ok := c.Raw()["role_mapping"].(map[string]any); ok {
		cfg.RoleMapping = make(map[string]string, len(rm))
		for k, v := range rm {
			if s, ok := v.(string); ok {
				cfg.RoleMapping[k] = s
			}
		}
	}
	p.cfg = cfg
	p.events = k.Events()
	p.log = k.Logger()
	return k.Registry().Provide(ServiceName, p)
}

func (p *Plugin) Start(ctx context.Context) error { p.started = true; return nil }
func (p *Plugin) Stop(ctx context.Context) error  { p.started = false; return nil }
func (p *Plugin) Health() api.Health {
	if p.started {
		return api.Health{Status: "ok"}
	}
	return api.Health{Status: "down"}
}

// Authenticate binds as the service account, searches for the user, then
// re-binds as the user to verify the password.
func (p *Plugin) Authenticate(ctx context.Context, credential any) (api.Principal, error) {
	cred, ok := credential.(Credential)
	if !ok {
		return api.Principal{}, fmt.Errorf("auth-ldap: credential must be an authldap.Credential, got %T", credential)
	}

	user, err := p.authenticate(cred.Username, cred.Password)
	if err != nil {
		p.deny(ctx, cred.Username, err)
		return api.Principal{}, err
	}
	principal := api.Principal{Subject: user.DN, Roles: user.Roles, Claims: map[string]any{
		"username": user.Username, "email": user.Email, "name": user.Name, "groups": user.Groups,
	}}
	if p.events != nil {
		p.events.Publish(ctx, api.Event{Topic: api.TopicAuthLogin, Source: PluginName, Payload: principal.Subject})
	}
	return principal, nil
}

func (p *Plugin) deny(ctx context.Context, subject string, reason error) {
	if p.events == nil {
		return
	}
	p.events.Publish(ctx, api.Event{
		Topic:   api.TopicAuthDenied,
		Source:  PluginName,
		Payload: map[string]any{"subject": subject, "reason": fmt.Sprint(reason)},
	})
}

// Authorize is a minimal placeholder: role "admin" allows everything.
// Real authorization decisions belong to the compliance plugin.
func (p *Plugin) Authorize(ctx context.Context, principal api.Principal, action, resource string) (bool, error) {
	for _, r := range principal.Roles {
		if r == "admin" {
			return true, nil
		}
	}
	return false, nil
}

func (p *Plugin) authenticate(username, password string) (*User, error) {
	cfg := p.cfg

	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap: connection failed: %w", err)
	}
	defer conn.Close()

	if err := bind(conn, cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: service bind failed: %w", err)
	}

	filter := strings.Replace(cfg.UserFilter, "%s", escapeFilter(username), 1)
	entries, err := search(conn, cfg.BaseDN, filter, []string{"dn", "uid", "cn", "mail", "sAMAccountName", "memberOf"})
	if err != nil {
		return nil, fmt.Errorf("ldap: user search failed: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("ldap: user %q not found", username)
	}
	userDN := entries[0]["dn"]
	if userDN == "" {
		return nil, fmt.Errorf("ldap: could not determine user DN")
	}

	conn2, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap: connection failed for user bind: %w", err)
	}
	defer conn2.Close()
	if err := bind(conn2, userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: authentication failed for user %q", username)
	}

	return p.buildUser(entries[0]), nil
}

func (p *Plugin) connect() (net.Conn, error) {
	cfg := p.cfg
	host := cfg.ServerURL
	useTLS := cfg.TLS
	if strings.HasPrefix(host, "ldaps://") {
		host, useTLS = strings.TrimPrefix(host, "ldaps://"), true
	} else if strings.HasPrefix(host, "ldap://") {
		host = strings.TrimPrefix(host, "ldap://")
	}
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":636"
		} else {
			host += ":389"
		}
	}
	dialer := net.Dialer{Timeout: cfg.Timeout}
	if useTLS {
		tlsHostname := host
		if idx := strings.LastIndex(tlsHostname, ":"); idx >= 0 {
			tlsHostname = tlsHostname[:idx]
		}
		tlsConfig := &tls.Config{ServerName: tlsHostname, InsecureSkipVerify: cfg.TLSInsecure}
		return tls.DialWithDialer(&dialer, "tcp", host, tlsConfig)
	}
	return dialer.Dial("tcp", host)
}

func (p *Plugin) buildUser(attrs map[string]string) *User {
	user := &User{DN: attrs["dn"], Attrs: attrs}
	switch {
	case attrs["uid"] != "":
		user.Username = attrs["uid"]
	case attrs["sAMAccountName"] != "":
		user.Username = attrs["sAMAccountName"]
	case attrs["cn"] != "":
		user.Username = attrs["cn"]
	}
	user.Email = attrs["mail"]
	user.Name = attrs["cn"]
	if v := attrs["memberOf"]; v != "" {
		user.Groups = strings.Split(v, ";")
	}
	if p.cfg.RoleMapping != nil {
		roleSet := map[string]struct{}{}
		for _, g := range user.Groups {
			if role, ok := p.cfg.RoleMapping[g]; ok {
				roleSet[role] = struct{}{}
			}
		}
		for r := range roleSet {
			user.Roles = append(user.Roles, r)
		}
	}
	return user
}

// ---- LDAP bind/search wire operations ----

func bind(conn net.Conn, dn, password string) error {
	version := berEncodeInteger(3)
	name := berEncodeOctetString([]byte(dn))
	authTLV := berEncodeContextPrimitive(0, []byte(password))
	bindBody := append(version, name...)
	bindBody = append(bindBody, authTLV...)
	bindReq := berEncodeApplication(ldapAppBindRequest, bindBody)
	msgID := berEncodeInteger(1)
	msg := berEncodeSequence(append(msgID, bindReq...))

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("failed to send bind request: %w", err)
	}
	respData, err := berReadMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read bind response: %w", err)
	}
	resultCode, errMsg := parseLDAPResult(respData)
	if resultCode != ldapResultSuccess {
		return fmt.Errorf("bind failed with code %d: %s", resultCode, errMsg)
	}
	return nil
}

func search(conn net.Conn, baseDN, filter string, attrs []string) ([]map[string]string, error) {
	searchBody := berEncodeOctetString([]byte(baseDN))
	searchBody = append(searchBody, berEncodeEnumerated(ldapScopeWholeSubtree)...)
	searchBody = append(searchBody, berEncodeEnumerated(ldapDerefNever)...)
	searchBody = append(searchBody, berEncodeInteger(1000)...)
	searchBody = append(searchBody, berEncodeInteger(30)...)
	searchBody = append(searchBody, berEncodeBoolean(false)...)
	searchBody = append(searchBody, berEncodeFilter(filter)...)

	var attrsBody []byte
	for _, attr := range attrs {
		attrsBody = append(attrsBody, berEncodeOctetString([]byte(attr))...)
	}
	searchBody = append(searchBody, berEncodeSequence(attrsBody)...)

	searchReq := berEncodeApplication(ldapAppSearchRequest, searchBody)
	msgID := berEncodeInteger(2)
	msg := berEncodeSequence(append(msgID, searchReq...))

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("failed to send search request: %w", err)
	}

	var entries []map[string]string
	for {
		respData, err := berReadMessage(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read search response: %w", err)
		}
		appTag := findApplicationTag(respData)
		if appTag == ldapAppSearchEntry {
			if entry := parseSearchEntry(respData); entry != nil {
				entries = append(entries, entry)
			}
		} else if appTag == ldapAppSearchDone {
			resultCode, errMsg := parseLDAPResult(respData)
			if resultCode != ldapResultSuccess {
				return nil, fmt.Errorf("search failed with code %d: %s", resultCode, errMsg)
			}
			break
		} else {
			break
		}
	}
	return entries, nil
}

// ---- BER-TLV encode/decode helpers (ported verbatim from v1) ----

func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buf []byte
	tmp := length
	for tmp > 0 {
		buf = append([]byte{byte(tmp & 0xFF)}, buf...)
		tmp >>= 8
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}

func berEncodeSequence(content []byte) []byte {
	return append(append([]byte{berTagSequence}, berEncodeLength(len(content))...), content...)
}

func berEncodeInteger(val int) []byte {
	if val == 0 {
		return []byte{berTagInteger, 0x01, 0x00}
	}
	var buf []byte
	v := val
	for v > 0 {
		buf = append([]byte{byte(v & 0xFF)}, buf...)
		v >>= 8
	}
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0x00}, buf...)
	}
	return append(append([]byte{berTagInteger}, berEncodeLength(len(buf))...), buf...)
}

func berEncodeOctetString(data []byte) []byte {
	return append(append([]byte{berTagOctetString}, berEncodeLength(len(data))...), data...)
}

func berEncodeEnumerated(val int) []byte { return []byte{berTagEnumerated, 0x01, byte(val)} }

func berEncodeBoolean(val bool) []byte {
	b := byte(0x00)
	if val {
		b = 0xFF
	}
	return []byte{berTagBoolean, 0x01, b}
}

func berEncodeContextPrimitive(tag int, data []byte) []byte {
	t := byte(berTagContextZero) | byte(tag)
	return append(append([]byte{t}, berEncodeLength(len(data))...), data...)
}

func berEncodeApplication(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, berEncodeLength(len(content))...), content...)
}

func berEncodeFilter(filter string) []byte {
	filter = strings.TrimSpace(filter)
	if strings.HasPrefix(filter, "(") && strings.HasSuffix(filter, ")") {
		filter = filter[1 : len(filter)-1]
	}
	if strings.HasPrefix(filter, "&") {
		return berEncodeFilterSet(0xA0, filter[1:])
	}
	if strings.HasPrefix(filter, "|") {
		return berEncodeFilterSet(0xA1, filter[1:])
	}
	if strings.HasPrefix(filter, "!") {
		inner := berEncodeFilter(filter[1:])
		return append(append([]byte{0xA2}, berEncodeLength(len(inner))...), inner...)
	}
	eqIdx := strings.Index(filter, "=")
	if eqIdx < 0 {
		return berEncodeOctetString([]byte(filter))
	}
	attr, val := filter[:eqIdx], filter[eqIdx+1:]
	if val == "*" {
		data := []byte(attr)
		return append(append([]byte{0x87}, berEncodeLength(len(data))...), data...)
	}
	if strings.Contains(val, "*") {
		return berEncodeSubstringFilter(attr, val)
	}
	body := berEncodeOctetString([]byte(attr))
	body = append(body, berEncodeOctetString([]byte(val))...)
	return append(append([]byte{0xA3}, berEncodeLength(len(body))...), body...)
}

func berEncodeSubstringFilter(attr, val string) []byte {
	parts := strings.Split(val, "*")
	var subsBody []byte
	for i, part := range parts {
		if part == "" {
			continue
		}
		var tag byte
		switch {
		case i == 0:
			tag = 0x80
		case i == len(parts)-1:
			tag = 0x82
		default:
			tag = 0x81
		}
		subsBody = append(subsBody, append(append([]byte{tag}, berEncodeLength(len(part))...), []byte(part)...)...)
	}
	body := berEncodeOctetString([]byte(attr))
	body = append(body, berEncodeSequence(subsBody)...)
	return append(append([]byte{0xA4}, berEncodeLength(len(body))...), body...)
}

func berEncodeFilterSet(tag byte, inner string) []byte {
	var encoded []byte
	depth, start := 0, -1
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				encoded = append(encoded, berEncodeFilter(inner[start:i+1])...)
				start = -1
			}
		}
	}
	return append(append([]byte{tag}, berEncodeLength(len(encoded))...), encoded...)
}

func berReadMessage(conn net.Conn) ([]byte, error) {
	tagBuf := make([]byte, 1)
	if _, err := conn.Read(tagBuf); err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 1)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}
	length := int(lenBuf[0])
	var lenBytes []byte
	if lenBuf[0]&0x80 != 0 {
		numBytes := int(lenBuf[0] & 0x7F)
		lenBytes = make([]byte, numBytes)
		if _, err := readFull(conn, lenBytes); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
	}
	content := make([]byte, length)
	if length > 0 {
		if _, err := readFull(conn, content); err != nil {
			return nil, err
		}
	}
	msg := append([]byte{tagBuf[0]}, lenBuf[0])
	if lenBuf[0]&0x80 != 0 {
		msg = append(msg, lenBytes...)
	}
	msg = append(msg, content...)
	return msg, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func findApplicationTag(data []byte) byte {
	offset := 0
	if offset >= len(data) || data[offset] != berTagSequence {
		return 0
	}
	offset++
	_, offset = berDecodeLength(data, offset)
	if offset >= len(data) || data[offset] != berTagInteger {
		return 0
	}
	offset++
	intLen, offset2 := berDecodeLength(data, offset)
	offset = offset2 + intLen
	if offset >= len(data) {
		return 0
	}
	return data[offset]
}

func parseLDAPResult(data []byte) (int, string) {
	offset := 0
	if offset >= len(data) || data[offset] != berTagSequence {
		return -1, "invalid response"
	}
	offset++
	_, offset = berDecodeLength(data, offset)
	if offset >= len(data) || data[offset] != berTagInteger {
		return -1, "invalid response"
	}
	offset++
	intLen, offset2 := berDecodeLength(data, offset)
	offset = offset2 + intLen
	if offset >= len(data) {
		return -1, "invalid response"
	}
	offset++
	_, offset = berDecodeLength(data, offset)
	if offset >= len(data) || data[offset] != berTagEnumerated {
		return -1, "invalid response"
	}
	offset++
	enumLen, offset3 := berDecodeLength(data, offset)
	offset = offset3
	resultCode := 0
	for i := 0; i < enumLen && offset+i < len(data); i++ {
		resultCode = resultCode<<8 | int(data[offset+i])
	}
	offset += enumLen
	if offset < len(data) && data[offset] == berTagOctetString {
		offset++
		sLen, newOffset := berDecodeLength(data, offset)
		offset = newOffset + sLen
	}
	errMsg := ""
	if offset < len(data) && data[offset] == berTagOctetString {
		offset++
		sLen, newOffset := berDecodeLength(data, offset)
		if newOffset+sLen <= len(data) {
			errMsg = string(data[newOffset : newOffset+sLen])
		}
	}
	return resultCode, errMsg
}

func parseSearchEntry(data []byte) map[string]string {
	result := make(map[string]string)
	offset := 0
	if offset >= len(data) || data[offset] != berTagSequence {
		return result
	}
	offset++
	_, offset = berDecodeLength(data, offset)
	if offset >= len(data) || data[offset] != berTagInteger {
		return result
	}
	offset++
	intLen, offset2 := berDecodeLength(data, offset)
	offset = offset2 + intLen
	if offset >= len(data) || data[offset] != ldapAppSearchEntry {
		return result
	}
	offset++
	_, offset = berDecodeLength(data, offset)
	if offset < len(data) && data[offset] == berTagOctetString {
		offset++
		sLen, newOffset := berDecodeLength(data, offset)
		if newOffset+sLen <= len(data) {
			result["dn"] = string(data[newOffset : newOffset+sLen])
		}
		offset = newOffset + sLen
	}
	if offset < len(data) && data[offset] == berTagSequence {
		offset++
		attrsLen, attrsOffset := berDecodeLength(data, offset)
		attrsEnd := attrsOffset + attrsLen
		for attrsOffset < attrsEnd && attrsOffset < len(data) {
			if data[attrsOffset] != berTagSequence {
				break
			}
			attrsOffset++
			_, attrStart := berDecodeLength(data, attrsOffset)
			attrsOffset = attrStart
			attrName := ""
			if attrsOffset < len(data) && data[attrsOffset] == berTagOctetString {
				attrsOffset++
				nameLen, nameStart := berDecodeLength(data, attrsOffset)
				if nameStart+nameLen <= len(data) {
					attrName = string(data[nameStart : nameStart+nameLen])
				}
				attrsOffset = nameStart + nameLen
			}
			if attrsOffset < len(data) && data[attrsOffset] == berTagSet {
				attrsOffset++
				setLen, setStart := berDecodeLength(data, attrsOffset)
				setEnd := setStart + setLen
				var values []string
				valOffset := setStart
				for valOffset < setEnd && valOffset < len(data) {
					if data[valOffset] != berTagOctetString {
						break
					}
					valOffset++
					vLen, vStart := berDecodeLength(data, valOffset)
					if vStart+vLen <= len(data) {
						values = append(values, string(data[vStart:vStart+vLen]))
					}
					valOffset = vStart + vLen
				}
				if len(values) > 0 {
					result[attrName] = strings.Join(values, ";")
				}
				attrsOffset = setEnd
			}
		}
	}
	return result
}

func berDecodeLength(data []byte, offset int) (int, int) {
	if offset >= len(data) {
		return 0, offset
	}
	b := data[offset]
	offset++
	if b&0x80 == 0 {
		return int(b), offset
	}
	numBytes := int(b & 0x7F)
	length := 0
	for i := 0; i < numBytes && offset < len(data); i++ {
		length = length<<8 | int(data[offset])
		offset++
	}
	return length, offset
}

func escapeFilter(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\\', '*', '(', ')', '\x00':
			fmt.Fprintf(&b, "\\%02x", c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

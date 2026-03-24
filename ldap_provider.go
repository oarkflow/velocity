package velocity

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// LDAP store key prefix
const ldapConfigPrefix = "ldap:config"

// LDAP BER-TLV tag constants
const (
	berTagSequence     = 0x30
	berTagSet          = 0x31
	berTagInteger      = 0x02
	berTagOctetString  = 0x04
	berTagEnumerated   = 0x0A
	berTagBoolean      = 0x01
	berTagContextZero  = 0x80 // context-specific primitive tag 0
	berTagContextThree = 0xA3 // context-specific constructed tag 3
)

// LDAP protocol constants
const (
	ldapAppBindRequest    = 0x60 // APPLICATION 0
	ldapAppBindResponse   = 0x61 // APPLICATION 1
	ldapAppSearchRequest  = 0x63 // APPLICATION 3
	ldapAppSearchEntry    = 0x64 // APPLICATION 4
	ldapAppSearchDone     = 0x65 // APPLICATION 5
	ldapAppUnbindRequest  = 0x42 // APPLICATION 2
	ldapResultSuccess     = 0
	ldapScopeWholeSubtree = 2
	ldapDerefNever        = 0
)

// LDAPConfig holds LDAP/Active Directory configuration.
type LDAPConfig struct {
	Name         string            `json:"name"`
	ServerURL    string            `json:"server_url"`    // e.g. ldap://ldap.example.com:389 or ldaps://...
	BindDN       string            `json:"bind_dn"`       // e.g. cn=admin,dc=example,dc=com
	BindPassword string            `json:"bind_password"`
	BaseDN       string            `json:"base_dn"`       // e.g. dc=example,dc=com
	UserFilter   string            `json:"user_filter"`   // e.g. (uid=%s) or (sAMAccountName=%s)
	GroupFilter  string            `json:"group_filter"`  // e.g. (member=%s)
	TLS          bool              `json:"tls"`
	TLSInsecure  bool              `json:"tls_insecure"`
	RoleMapping  map[string]string `json:"role_mapping"`  // LDAP group DN -> Velocity role
	Timeout      time.Duration     `json:"timeout"`
}

// LDAPUser represents a user retrieved from LDAP.
type LDAPUser struct {
	DN       string            `json:"dn"`
	Username string            `json:"username"`
	Email    string            `json:"email"`
	Name     string            `json:"name"`
	Groups   []string          `json:"groups"`
	Roles    []string          `json:"roles"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// LDAPProvider handles LDAP authentication and user lookups.
type LDAPProvider struct {
	config *LDAPConfig
	db     *DB
	mu     sync.RWMutex
}

// NewLDAPProvider creates a new LDAP provider with the given configuration.
func NewLDAPProvider(db *DB, config *LDAPConfig) *LDAPProvider {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.UserFilter == "" {
		config.UserFilter = "(uid=%s)"
	}
	if config.GroupFilter == "" {
		config.GroupFilter = "(member=%s)"
	}
	return &LDAPProvider{
		config: config,
		db:     db,
	}
}

// SaveConfig persists the LDAP configuration to the DB.
func (p *LDAPProvider) SaveConfig() error {
	data, err := json.Marshal(p.config)
	if err != nil {
		return fmt.Errorf("ldap: failed to marshal config: %w", err)
	}
	return p.db.Put([]byte(ldapConfigPrefix), data)
}

// LoadLDAPConfig loads the LDAP configuration from the DB.
func LoadLDAPConfig(db *DB) (*LDAPConfig, error) {
	data, err := db.Get([]byte(ldapConfigPrefix))
	if err != nil {
		return nil, fmt.Errorf("ldap: config not found: %w", err)
	}
	var cfg LDAPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("ldap: failed to unmarshal config: %w", err)
	}
	return &cfg, nil
}

// Authenticate verifies user credentials against the LDAP server.
func (p *LDAPProvider) Authenticate(username, password string) (*LDAPUser, error) {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap: connection failed: %w", err)
	}
	defer conn.Close()

	// Bind with service account
	if err := p.bind(conn, cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: service bind failed: %w", err)
	}

	// Search for user
	filter := strings.Replace(cfg.UserFilter, "%s", ldapEscapeFilter(username), 1)
	entries, err := p.search(conn, cfg.BaseDN, filter, []string{"dn", "uid", "cn", "mail", "sAMAccountName", "memberOf"})
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

	// Re-bind as the user to verify password
	conn2, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap: connection failed for user bind: %w", err)
	}
	defer conn2.Close()

	if err := p.bind(conn2, userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: authentication failed for user %q", username)
	}

	// Build user from search results
	return p.buildUser(entries[0]), nil
}

// GetUserGroups retrieves the groups for a given user DN.
func (p *LDAPProvider) GetUserGroups(userDN string) ([]string, error) {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := p.bind(conn, cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, err
	}

	filter := strings.Replace(cfg.GroupFilter, "%s", ldapEscapeFilter(userDN), 1)
	entries, err := p.search(conn, cfg.BaseDN, filter, []string{"dn", "cn"})
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(entries))
	for _, entry := range entries {
		if dn, ok := entry["dn"]; ok && dn != "" {
			groups = append(groups, dn)
		}
	}
	return groups, nil
}

// SearchUser searches for a user by filter.
func (p *LDAPProvider) SearchUser(username string) (*LDAPUser, error) {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := p.bind(conn, cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, err
	}

	filter := strings.Replace(cfg.UserFilter, "%s", ldapEscapeFilter(username), 1)
	entries, err := p.search(conn, cfg.BaseDN, filter, []string{"dn", "uid", "cn", "mail", "sAMAccountName", "memberOf"})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("ldap: user %q not found", username)
	}

	return p.buildUser(entries[0]), nil
}

// MapToVelocityUser converts an LDAP user to the Velocity user model.
func (p *LDAPProvider) MapToVelocityUser(ldapUser *LDAPUser) *User {
	return &User{
		ID:       ldapUser.DN,
		Username: ldapUser.Username,
		Email:    ldapUser.Email,
		Roles:    ldapUser.Roles,
		Active:   true,
		Attributes: map[string]string{
			"source": "ldap",
			"dn":     ldapUser.DN,
			"name":   ldapUser.Name,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// TestConnection verifies that the LDAP server is reachable and the bind credentials work.
func (p *LDAPProvider) TestConnection() error {
	conn, err := p.connect()
	if err != nil {
		return fmt.Errorf("ldap: connection test failed: %w", err)
	}
	defer conn.Close()

	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	if err := p.bind(conn, cfg.BindDN, cfg.BindPassword); err != nil {
		return fmt.Errorf("ldap: bind test failed: %w", err)
	}

	// Unbind cleanly
	_ = p.unbind(conn)
	return nil
}

// connect establishes a TCP connection to the LDAP server.
func (p *LDAPProvider) connect() (net.Conn, error) {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	serverURL := cfg.ServerURL
	useTLS := cfg.TLS

	// Parse URL scheme
	host := serverURL
	if strings.HasPrefix(serverURL, "ldaps://") {
		host = strings.TrimPrefix(serverURL, "ldaps://")
		useTLS = true
	} else if strings.HasPrefix(serverURL, "ldap://") {
		host = strings.TrimPrefix(serverURL, "ldap://")
	}

	// Add default port if missing
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
		tlsConfig := &tls.Config{
			ServerName:         tlsHostname,
			InsecureSkipVerify: cfg.TLSInsecure,
		}
		return tls.DialWithDialer(&dialer, "tcp", host, tlsConfig)
	}

	return dialer.Dial("tcp", host)
}

// bind performs an LDAP simple bind operation.
func (p *LDAPProvider) bind(conn net.Conn, dn, password string) error {
	// Build Bind Request:
	// BindRequest ::= [APPLICATION 0] SEQUENCE {
	//     version     INTEGER (3),
	//     name        LDAPDN,
	//     authentication AuthenticationChoice (simple [0] OCTET STRING)
	// }
	version := berEncodeInteger(3)
	name := berEncodeOctetString([]byte(dn))
	auth := berEncodeContextPrimitive(0, []byte(password))

	bindBody := append(version, name...)
	bindBody = append(bindBody, auth...)

	bindReq := berEncodeApplication(ldapAppBindRequest, bindBody)
	msgID := berEncodeInteger(1)
	msg := berEncodeSequence(append(msgID, bindReq...))

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("failed to send bind request: %w", err)
	}

	// Read response
	respData, err := berReadMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read bind response: %w", err)
	}

	// Parse the result code from the bind response
	resultCode, errMsg := parseLDAPResult(respData)
	if resultCode != ldapResultSuccess {
		return fmt.Errorf("bind failed with code %d: %s", resultCode, errMsg)
	}

	return nil
}

// unbind sends an LDAP unbind request.
func (p *LDAPProvider) unbind(conn net.Conn) error {
	// UnbindRequest ::= [APPLICATION 2] NULL
	unbindReq := []byte{ldapAppUnbindRequest, 0x00}
	msgID := berEncodeInteger(2)
	msg := berEncodeSequence(append(msgID, unbindReq...))

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(msg)
	return err
}

// search performs an LDAP search and returns entries as maps of attribute name -> value.
func (p *LDAPProvider) search(conn net.Conn, baseDN, filter string, attrs []string) ([]map[string]string, error) {
	// SearchRequest ::= [APPLICATION 3] SEQUENCE {
	//     baseObject   LDAPDN,
	//     scope        ENUMERATED,
	//     derefAliases ENUMERATED,
	//     sizeLimit    INTEGER,
	//     timeLimit    INTEGER,
	//     typesOnly    BOOLEAN,
	//     filter       Filter,
	//     attributes   AttributeDescriptionList
	// }
	searchBody := berEncodeOctetString([]byte(baseDN))
	searchBody = append(searchBody, berEncodeEnumerated(ldapScopeWholeSubtree)...)
	searchBody = append(searchBody, berEncodeEnumerated(ldapDerefNever)...)
	searchBody = append(searchBody, berEncodeInteger(1000)...) // sizeLimit
	searchBody = append(searchBody, berEncodeInteger(30)...)   // timeLimit
	searchBody = append(searchBody, berEncodeBoolean(false)...)
	searchBody = append(searchBody, berEncodeFilter(filter)...)

	// Encode attributes list as SEQUENCE of OCTET STRING
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

	// Read search responses - may receive multiple SearchResultEntry followed by SearchResultDone
	var entries []map[string]string
	for {
		respData, err := berReadMessage(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read search response: %w", err)
		}

		// Parse the outer SEQUENCE: messageID, protocolOp
		appTag := findApplicationTag(respData)

		if appTag == ldapAppSearchEntry {
			entry := parseSearchEntry(respData)
			if entry != nil {
				entries = append(entries, entry)
			}
		} else if appTag == ldapAppSearchDone {
			resultCode, errMsg := parseLDAPResult(respData)
			if resultCode != ldapResultSuccess {
				return nil, fmt.Errorf("search failed with code %d: %s", resultCode, errMsg)
			}
			break
		} else {
			// Unknown response, skip
			break
		}
	}

	return entries, nil
}

// buildUser creates an LDAPUser from search result attributes.
func (p *LDAPProvider) buildUser(attrs map[string]string) *LDAPUser {
	user := &LDAPUser{
		DN:    attrs["dn"],
		Attrs: attrs,
	}

	// Extract username from known attributes
	if v, ok := attrs["uid"]; ok && v != "" {
		user.Username = v
	} else if v, ok := attrs["sAMAccountName"]; ok && v != "" {
		user.Username = v
	} else if v, ok := attrs["cn"]; ok && v != "" {
		user.Username = v
	}

	if v, ok := attrs["mail"]; ok {
		user.Email = v
	}
	if v, ok := attrs["cn"]; ok {
		user.Name = v
	}

	// Parse memberOf attribute (simplified - LDAP may return multiple values)
	if v, ok := attrs["memberOf"]; ok && v != "" {
		user.Groups = strings.Split(v, ";")
	}

	// Map groups to roles
	p.mu.RLock()
	roleMapping := p.config.RoleMapping
	p.mu.RUnlock()

	if roleMapping != nil {
		roleSet := make(map[string]struct{})
		for _, group := range user.Groups {
			if role, ok := roleMapping[group]; ok {
				roleSet[role] = struct{}{}
			}
		}
		for role := range roleSet {
			user.Roles = append(user.Roles, role)
		}
	}
	if len(user.Roles) == 0 {
		user.Roles = []string{RoleUser}
	}

	return user
}

// ---- BER-TLV encoding helpers ----

func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Multi-byte length
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
	// Add leading zero if high bit set
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0x00}, buf...)
	}
	return append(append([]byte{berTagInteger}, berEncodeLength(len(buf))...), buf...)
}

func berEncodeOctetString(data []byte) []byte {
	return append(append([]byte{berTagOctetString}, berEncodeLength(len(data))...), data...)
}

func berEncodeEnumerated(val int) []byte {
	return []byte{berTagEnumerated, 0x01, byte(val)}
}

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

// berEncodeFilter encodes a simple LDAP filter string.
// Supports simple equality filters like (uid=value) and present filters like (objectClass=*).
// For a production system, this would need a full filter parser.
func berEncodeFilter(filter string) []byte {
	filter = strings.TrimSpace(filter)
	if strings.HasPrefix(filter, "(") && strings.HasSuffix(filter, ")") {
		filter = filter[1 : len(filter)-1]
	}

	// Handle AND filter (&...)
	if strings.HasPrefix(filter, "&") {
		inner := filter[1:]
		return berEncodeFilterSet(0xA0, inner) // context 0 = AND
	}
	// Handle OR filter (|...)
	if strings.HasPrefix(filter, "|") {
		inner := filter[1:]
		return berEncodeFilterSet(0xA1, inner) // context 1 = OR
	}
	// Handle NOT filter (!...)
	if strings.HasPrefix(filter, "!") {
		inner := filter[1:]
		innerEncoded := berEncodeFilter(inner)
		return append(append([]byte{0xA2}, berEncodeLength(len(innerEncoded))...), innerEncoded...)
	}

	// Simple equality or present filter
	eqIdx := strings.Index(filter, "=")
	if eqIdx < 0 {
		// Fallback: encode as octet string
		return berEncodeOctetString([]byte(filter))
	}

	attr := filter[:eqIdx]
	val := filter[eqIdx+1:]

	// Present filter: (attr=*)
	if val == "*" {
		data := []byte(attr)
		return append(append([]byte{0x87}, berEncodeLength(len(data))...), data...)
	}

	// Substring filter: (attr=*val*) or (attr=val*) or (attr=*val)
	if strings.Contains(val, "*") {
		return berEncodeSubstringFilter(attr, val)
	}

	// Equality filter: (attr=val)
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
		if i == 0 {
			tag = 0x80 // initial
		} else if i == len(parts)-1 {
			tag = 0x82 // final
		} else {
			tag = 0x81 // any
		}
		subsBody = append(subsBody, append(append([]byte{tag}, berEncodeLength(len(part))...), []byte(part)...)...)
	}

	body := berEncodeOctetString([]byte(attr))
	body = append(body, berEncodeSequence(subsBody)...)
	return append(append([]byte{0xA4}, berEncodeLength(len(body))...), body...)
}

func berEncodeFilterSet(tag byte, inner string) []byte {
	// Parse sub-filters from the inner string
	var encoded []byte
	depth := 0
	start := -1
	for i := 0; i < len(inner); i++ {
		if inner[i] == '(' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if inner[i] == ')' {
			depth--
			if depth == 0 && start >= 0 {
				subFilter := inner[start : i+1]
				encoded = append(encoded, berEncodeFilter(subFilter)...)
				start = -1
			}
		}
	}
	return append(append([]byte{tag}, berEncodeLength(len(encoded))...), encoded...)
}

// berReadMessage reads a single BER-encoded LDAP message from a connection.
func berReadMessage(conn net.Conn) ([]byte, error) {
	// Read tag
	tagBuf := make([]byte, 1)
	if _, err := conn.Read(tagBuf); err != nil {
		return nil, err
	}

	// Read length
	lenBuf := make([]byte, 1)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}

	length := int(lenBuf[0])
	if lenBuf[0]&0x80 != 0 {
		numBytes := int(lenBuf[0] & 0x7F)
		lenBytes := make([]byte, numBytes)
		if _, err := readFull(conn, lenBytes); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
	}

	// Read content
	content := make([]byte, length)
	if length > 0 {
		if _, err := readFull(conn, content); err != nil {
			return nil, err
		}
	}

	// Reconstruct full message
	msg := append([]byte{tagBuf[0]}, lenBuf[0])
	if lenBuf[0]&0x80 != 0 {
		numBytes := int(lenBuf[0] & 0x7F)
		lenBytes := make([]byte, numBytes)
		// Re-encode length bytes
		tmp := length
		for i := numBytes - 1; i >= 0; i-- {
			lenBytes[i] = byte(tmp & 0xFF)
			tmp >>= 8
		}
		msg = append(msg, lenBytes...)
	}
	msg = append(msg, content...)

	return msg, nil
}

// readFull reads exactly len(buf) bytes from conn.
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

// findApplicationTag scans a BER-encoded LDAP message for the application tag.
func findApplicationTag(data []byte) byte {
	// LDAP message: SEQUENCE { messageID INTEGER, protocolOp APPLICATION ... }
	// Skip the outer SEQUENCE tag and length
	offset := 0
	if offset >= len(data) {
		return 0
	}
	if data[offset] != berTagSequence {
		return 0
	}
	offset++
	_, offset = berDecodeLength(data, offset)

	// Skip messageID (INTEGER)
	if offset >= len(data) || data[offset] != berTagInteger {
		return 0
	}
	offset++
	intLen, offset := berDecodeLength(data, offset)
	offset += intLen

	// The next byte is the application tag
	if offset >= len(data) {
		return 0
	}
	return data[offset]
}

// parseLDAPResult extracts the result code and error message from an LDAP response.
func parseLDAPResult(data []byte) (int, string) {
	// Navigate past SEQUENCE tag/length, messageID, application tag/length
	offset := 0
	if offset >= len(data) || data[offset] != berTagSequence {
		return -1, "invalid response"
	}
	offset++
	_, offset = berDecodeLength(data, offset)

	// Skip messageID
	if offset >= len(data) || data[offset] != berTagInteger {
		return -1, "invalid response"
	}
	offset++
	intLen, offset := berDecodeLength(data, offset)
	offset += intLen

	// Application tag
	if offset >= len(data) {
		return -1, "invalid response"
	}
	offset++ // skip tag
	_, offset = berDecodeLength(data, offset)

	// Result code (ENUMERATED)
	if offset >= len(data) || data[offset] != berTagEnumerated {
		return -1, "invalid response"
	}
	offset++
	enumLen, offset := berDecodeLength(data, offset)
	resultCode := 0
	for i := 0; i < enumLen && offset+i < len(data); i++ {
		resultCode = resultCode<<8 | int(data[offset+i])
	}
	offset += enumLen

	// Matched DN (OCTET STRING) - skip
	if offset < len(data) && data[offset] == berTagOctetString {
		offset++
		sLen, newOffset := berDecodeLength(data, offset)
		offset = newOffset + sLen
	}

	// Error message (OCTET STRING)
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

// parseSearchEntry extracts attributes from a SearchResultEntry.
func parseSearchEntry(data []byte) map[string]string {
	result := make(map[string]string)

	// Navigate to the search entry content
	offset := 0
	if offset >= len(data) || data[offset] != berTagSequence {
		return result
	}
	offset++
	_, offset = berDecodeLength(data, offset)

	// Skip messageID
	if offset >= len(data) || data[offset] != berTagInteger {
		return result
	}
	offset++
	intLen, offset2 := berDecodeLength(data, offset)
	offset = offset2 + intLen

	// SearchResultEntry APPLICATION tag
	if offset >= len(data) || data[offset] != ldapAppSearchEntry {
		return result
	}
	offset++
	_, offset = berDecodeLength(data, offset)

	// Object DN (OCTET STRING)
	if offset < len(data) && data[offset] == berTagOctetString {
		offset++
		sLen, newOffset := berDecodeLength(data, offset)
		if newOffset+sLen <= len(data) {
			result["dn"] = string(data[newOffset : newOffset+sLen])
		}
		offset = newOffset + sLen
	}

	// Attributes SEQUENCE of SEQUENCE { type OCTET STRING, vals SET of OCTET STRING }
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

			// Attribute type (OCTET STRING)
			attrName := ""
			if attrsOffset < len(data) && data[attrsOffset] == berTagOctetString {
				attrsOffset++
				nameLen, nameStart := berDecodeLength(data, attrsOffset)
				if nameStart+nameLen <= len(data) {
					attrName = string(data[nameStart : nameStart+nameLen])
				}
				attrsOffset = nameStart + nameLen
			}

			// Attribute values (SET of OCTET STRING)
			if attrsOffset < len(data) && data[attrsOffset] == berTagSet {
				attrsOffset++
				setLen, setStart := berDecodeLength(data, attrsOffset)
				setEnd := setStart + setLen

				var values []string
				valOffset := setStart
				for valOffset < setEnd && valOffset < len(data) {
					if data[valOffset] == berTagOctetString {
						valOffset++
						vLen, vStart := berDecodeLength(data, valOffset)
						if vStart+vLen <= len(data) {
							values = append(values, string(data[vStart:vStart+vLen]))
						}
						valOffset = vStart + vLen
					} else {
						break
					}
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

// berDecodeLength decodes a BER length at the given offset and returns (length, new offset).
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

// ldapEscapeFilter escapes special characters in LDAP filter values.
func ldapEscapeFilter(s string) string {
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

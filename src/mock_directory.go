package main

import (
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// MockEntry represents an in-memory LDAP entry for zero-dependency testing in Cloud Run
// when a provider uses a "mock://" URL while still exercising all RFC 4515/4514 escaping,
// Write Base DN AST validation, multivalue formatting, and LDIF parsing.
type MockEntry struct {
	DN         string
	Password   string
	Attributes map[string][]string
}

type MockDirectory struct {
	mu          sync.RWMutex
	entries     map[string]*MockEntry // keyed by lowercase DN
	parentGroup map[string][]string   // childGroupDN (lower) -> parentGroupDNs (for AD nested group 1.2.840.113556.1.4.1941)
}

var defaultMockDir = NewMockDirectory()

func NewMockDirectory() *MockDirectory {
	m := &MockDirectory{
		entries:     make(map[string]*MockEntry),
		parentGroup: make(map[string][]string),
	}
	m.seed()
	return m
}

func (m *MockDirectory) seed() {
	users := []*MockEntry{
		{
			DN:       "cn=jdoe,ou=Subscribers,dc=enterprise,dc=com",
			Password: "SecretPassword123",
			Attributes: map[string][]string{
				"objectClass":     {"top", "person", "organizationalPerson", "user", "inetOrgPerson"},
				"cn":              {"jdoe"},
				"uid":             {"jdoe"},
				"sAMAccountName":  {"jdoe"},
				"mail":            {"jdoe@enterprise.com"},
				"displayName":     {"John Doe"},
				"department":      {"Core Network APIs"},
				"telephoneNumber": {"+34-91-555-0100"},
				"memberOf": {
					"CN=API-Consumers,OU=Groups,DC=enterprise,DC=com",
					"CN=Core-Engineers,OU=Groups,DC=enterprise,DC=com",
				},
			},
		},
		{
			DN:       "cn=carlos.ruiz,ou=Subscribers,dc=enterprise,dc=com",
			Password: "Enterprise2026!",
			Attributes: map[string][]string{
				"objectClass":     {"top", "person", "organizationalPerson", "user", "inetOrgPerson"},
				"cn":              {"carlos.ruiz"},
				"uid":             {"carlos.ruiz"},
				"sAMAccountName":  {"carlos.ruiz"},
				"mail":            {"carlos.ruiz@enterprise.com"},
				"displayName":     {"Carlos Ruiz"},
				"department":      {"Open Gateway"},
				"telephoneNumber": {"+34-91-555-0200"},
				"memberOf": {
					"CN=Core-Engineers,OU=Groups,DC=enterprise,DC=com",
				},
			},
		},
		{
			DN:       "cn=guest,ou=Subscribers,dc=enterprise,dc=com",
			Password: "GuestPass123",
			Attributes: map[string][]string{
				"objectClass":    {"top", "person", "user"},
				"cn":             {"guest"},
				"uid":            {"guest"},
				"sAMAccountName": {"guest"},
				"mail":           {"guest@enterprise.com"},
				"displayName":    {"External Guest"},
				"department":     {"External"},
				"memberOf": {
					"CN=Guests,OU=Groups,DC=enterprise,DC=com",
				},
			},
		},
	}
	for _, u := range users {
		m.entries[strings.ToLower(u.DN)] = u
	}
	// Nested group hierarchy: Core-Engineers is a child of API-Admins and API-Consumers
	m.parentGroup[strings.ToLower("CN=Core-Engineers,OU=Groups,DC=enterprise,DC=com")] = []string{
		"CN=API-Admins,OU=Groups,DC=enterprise,DC=com",
		"CN=API-Consumers,OU=Groups,DC=enterprise,DC=com",
	}
}

func isMockProvider(cfg *Config) bool {
	for _, u := range cfg.LDAPURLs {
		if strings.HasPrefix(strings.ToLower(u), "mock://") {
			return true
		}
	}
	return false
}

var attrEqRegex = regexp.MustCompile(`\(([a-zA-Z0-9_-]+)=([^()]+)\)`)

func (m *MockDirectory) Search(baseDN, filter string, requestedAttrs []string, mode string) ([]QueryEntryItem, map[string]any, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clauses := attrEqRegex.FindAllStringSubmatch(filter, -1)
	var items []QueryEntryItem
	var firstVars map[string]any
	var firstDN string

	for _, entry := range m.entries {
		if baseDN != "" && ValidateWriteBaseDN(entry.DN, baseDN) != nil {
			continue
		}
		matched := true
		for _, c := range clauses {
			attrName := c[1]
			expectedVal := c[2]
			if expectedVal == "*" {
				continue
			}
			found := false
			for k, vals := range entry.Attributes {
				if strings.EqualFold(k, attrName) {
					for _, v := range vals {
						if strings.EqualFold(v, expectedVal) {
							found = true
							break
						}
					}
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		formatted := FormatMockAttributes(entry, requestedAttrs, mode)
		items = append(items, QueryEntryItem{
			DN:         entry.DN,
			Attributes: formatted,
		})
		if firstVars == nil {
			firstVars = formatted
			firstDN = entry.DN
		}
	}
	return items, firstVars, firstDN
}

func FormatMockAttributes(entry *MockEntry, requested []string, mode string) map[string]any {
	out := make(map[string]any)
	upperMode := strings.ToUpper(strings.TrimSpace(mode))
	if upperMode == "" {
		upperMode = "FIRST"
	}
	attrsToRead := requested
	if len(attrsToRead) == 0 {
		for k := range entry.Attributes {
			attrsToRead = append(attrsToRead, k)
		}
	}
	for _, reqAttr := range attrsToRead {
		var vals []string
		for k, v := range entry.Attributes {
			if strings.EqualFold(k, reqAttr) {
				vals = v
				break
			}
		}
		if len(vals) == 0 {
			out[reqAttr] = ""
			continue
		}
		switch upperMode {
		case "JOIN_COMMA", "CSV":
			out[reqAttr] = strings.Join(vals, ",")
		case "ARRAY", "MULTIVALUE":
			out[reqAttr] = vals
		default:
			out[reqAttr] = vals[0]
		}
	}
	return out
}

func (m *MockDirectory) HasGroup(entry *MockEntry, reqGroup string, resolveNested bool) bool {
	for k, vals := range entry.Attributes {
		if strings.EqualFold(k, "memberOf") {
			for _, g := range vals {
				if strings.EqualFold(g, reqGroup) || strings.HasPrefix(strings.ToLower(g), "cn="+strings.ToLower(reqGroup)+",") {
					return true
				}
				if resolveNested {
					for _, parent := range m.parentGroup[strings.ToLower(g)] {
						if strings.EqualFold(parent, reqGroup) || strings.HasPrefix(strings.ToLower(parent), "cn="+strings.ToLower(reqGroup)+",") {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (m *MockDirectory) Authenticate(req AuthenticateLDAPRequest, cfg *Config, baseDN string) (int, AuthenticateLDAPResponse) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matchedEntry *MockEntry
	for _, entry := range m.entries {
		if baseDN != "" && ValidateWriteBaseDN(entry.DN, baseDN) != nil {
			continue
		}
		for k, vals := range entry.Attributes {
			if strings.EqualFold(k, cfg.Profile.UserLoginAttr) || strings.EqualFold(k, "uid") || strings.EqualFold(k, "cn") || strings.EqualFold(k, "sAMAccountName") {
				for _, v := range vals {
					if strings.EqualFold(v, req.Username) {
						matchedEntry = entry
						break
					}
				}
			}
		}
		if matchedEntry != nil {
			break
		}
	}

	if matchedEntry == nil {
		return http.StatusUnauthorized, AuthenticateLDAPResponse{
			Authenticated: false,
			Authorized:    false,
			ProviderID:    cfg.ID,
			Error:         &LDAPPolicyError{Code: ldap.LDAPResultInvalidCredentials, ResultName: "USER_NOT_FOUND", Message: "user not found in directory"},
		}
	}

	if matchedEntry.Password != req.Password {
		return http.StatusUnauthorized, AuthenticateLDAPResponse{
			Authenticated: false,
			Authorized:    false,
			ProviderID:    cfg.ID,
			DN:            matchedEntry.DN,
			Error:         &LDAPPolicyError{Code: ldap.LDAPResultInvalidCredentials, ResultName: "INVALID_CREDENTIALS", Message: "LDAP Result Code 49 \"Invalid Credentials\""},
		}
	}

	authorized := checkAllowedUsers(req.Username, matchedEntry.DN, req.RequireUsers)
	if authorized && len(req.RequireGroups) > 0 {
		groupOK := false
		for _, rg := range req.RequireGroups {
			if strings.TrimSpace(rg) == "" {
				groupOK = true
				break
			}
			if m.HasGroup(matchedEntry, rg, req.ResolveNestedAD && cfg.Profile.SupportsADInChain) {
				groupOK = true
				break
			}
		}
		authorized = groupOK
	}

	var groups []string
	for k, vals := range matchedEntry.Attributes {
		if strings.EqualFold(k, "memberOf") {
			groups = append(groups, vals...)
		}
	}

	vars := FormatMockAttributes(matchedEntry, req.ReturnAttributes, req.MultivalueMode)
	status := http.StatusOK
	var authErr *LDAPPolicyError
	if !authorized {
		status = http.StatusForbidden
		authErr = &LDAPPolicyError{
			Code:       ldap.LDAPResultInsufficientAccessRights,
			ResultName: "INSUFFICIENT_ACCESS_RIGHTS",
			Message:    "user is authenticated but does not belong to required LDAP group",
		}
	}

	return status, AuthenticateLDAPResponse{
		Authenticated: true,
		Authorized:    authorized,
		ProviderID:    cfg.ID,
		DN:            matchedEntry.DN,
		Groups:        groups,
		Variables:     vars,
		Error:         authErr,
	}
}

func (m *MockDirectory) ExecuteWrite(req WriteLDAPRequest, writeBaseDN string, protect bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.TrimSpace(req.LDIFTemplate) != "" {
		rendered := RenderDN(req.LDIFTemplate, req.Variables, protect)
		scanner := bufio.NewScanner(strings.NewReader(rendered))
		var targetDN, changeType, modOp, modAttr string
		attrs := make(map[string][]string)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || line == "-" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := strings.TrimSpace(parts[1])
			switch k {
			case "dn":
				targetDN = v
			case "changetype":
				changeType = strings.ToLower(v)
			case "replace", "add", "delete":
				modOp = k
				modAttr = v
			default:
				if changeType == "modify" && modAttr != "" && strings.EqualFold(k, modAttr) {
					attrs[modAttr] = append(attrs[modAttr], v)
				} else {
					attrs[parts[0]] = append(attrs[parts[0]], v)
				}
			}
		}
		if err := ValidateWriteBaseDN(targetDN, writeBaseDN); err != nil {
			return targetDN, &ldap.Error{
				ResultCode: ldap.LDAPResultInsufficientAccessRights,
				Err:        err,
			}
		}
		key := strings.ToLower(targetDN)
		switch changeType {
		case "add":
			m.entries[key] = &MockEntry{DN: targetDN, Attributes: attrs}
		case "modify":
			entry, ok := m.entries[key]
			if !ok {
				return targetDN, &ldap.Error{
					ResultCode: ldap.LDAPResultNoSuchObject,
					Err:        fmt.Errorf("entry %q not found", targetDN),
				}
			}
			if modOp == "delete" {
				delete(entry.Attributes, modAttr)
			} else if modAttr != "" {
				entry.Attributes[modAttr] = attrs[modAttr]
			}
		case "delete":
			delete(m.entries, key)
		}
		return targetDN, nil
	}

	targetDN := RenderDN(req.DN, req.Variables, protect)
	if err := ValidateWriteBaseDN(targetDN, writeBaseDN); err != nil {
		return targetDN, &ldap.Error{
			ResultCode: ldap.LDAPResultInsufficientAccessRights,
			Err:        err,
		}
	}
	return targetDN, nil
}

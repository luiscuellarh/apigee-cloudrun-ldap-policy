package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const maxRequestBodyBytes = 1 << 20 // 1 MB limit

type Server struct {
	registry *ProviderRegistry
}

// --- 1. Query LDAP Operation Payloads ---

type QueryLDAPRequest struct {
	ProviderID           string            `json:"provider_id"` // Mandatory Target LDAP Identity Provider ID
	BaseDN               string            `json:"base_dn,omitempty"`
	Scope                string            `json:"scope,omitempty"`  // "BASE", "ONE", "SUB" (default "SUB")
	Filter               string            `json:"filter,omitempty"` // e.g. "(&(objectClass=user)(sAMAccountName=$[username]))"
	FilterVariables      map[string]string `json:"filter_variables,omitempty"`
	ProtectLDAPInjection *bool             `json:"protect_ldap_injection,omitempty"` // Default: true (RFC 4515 escaping)
	Attributes           []string          `json:"attributes"`
	MultivalueMode       string            `json:"multivalue_mode,omitempty"` // "FIRST" (default), "JOIN_COMMA", "ARRAY"
	MaxResults           int               `json:"max_results,omitempty"`
}

type QueryLDAPResponse struct {
	Success    bool             `json:"success"`
	ProviderID string           `json:"provider_id,omitempty"`
	Count      int              `json:"count"`
	DN         string           `json:"dn,omitempty"`
	Variables  map[string]any   `json:"variables,omitempty"`
	Entries    []QueryEntryItem `json:"entries,omitempty"`
	Error      *LDAPPolicyError `json:"error,omitempty"`
}

type QueryEntryItem struct {
	DN         string         `json:"dn"`
	Attributes map[string]any `json:"attributes"`
}

// --- 2. Write LDAP Operation Payloads ---

type WriteLDAPRequest struct {
	ProviderID           string              `json:"provider_id"` // Mandatory Target LDAP Identity Provider ID
	LDIFTemplate         string              `json:"ldif_template,omitempty"`
	Variables            map[string]string   `json:"variables,omitempty"`
	ProtectLDAPInjection *bool               `json:"protect_ldap_injection,omitempty"`
	Operation            string              `json:"operation,omitempty"` // "ADD", "MODIFY", "DELETE"
	DN                   string              `json:"dn,omitempty"`
	AddAttributes        map[string][]string `json:"add_attributes,omitempty"`
	Modifications        []LDAPModification  `json:"modifications,omitempty"`
}

type LDAPModification struct {
	Action    string   `json:"action"` // "add", "replace", "delete"
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
}

type WriteLDAPResponse struct {
	Success    bool             `json:"success"`
	ProviderID string           `json:"provider_id,omitempty"`
	DN         string           `json:"dn,omitempty"`
	Error      *LDAPPolicyError `json:"error,omitempty"`
}

// --- 3. Authenticate User or Group Operation Payloads ---

type AuthenticateLDAPRequest struct {
	ProviderID       string   `json:"provider_id"` // Mandatory Target LDAP Identity Provider ID
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	BaseDN           string   `json:"base_dn,omitempty"`
	UserSearchFilter string   `json:"user_search_filter,omitempty"`
	RequireUsers     []string `json:"require_users,omitempty"`
	RequireGroups    []string `json:"require_groups,omitempty"`
	ResolveNestedAD  bool     `json:"resolve_nested_ad,omitempty"`
	ReturnAttributes []string `json:"return_attributes,omitempty"`
	MultivalueMode   string   `json:"multivalue_mode,omitempty"`
}

type AuthenticateLDAPResponse struct {
	Authenticated bool             `json:"authenticated"`
	Authorized    bool             `json:"authorized"`
	ProviderID    string           `json:"provider_id,omitempty"`
	DN            string           `json:"dn,omitempty"`
	Groups        []string         `json:"groups,omitempty"`
	Variables     map[string]any   `json:"variables,omitempty"`
	Error         *LDAPPolicyError `json:"error,omitempty"`
}

type LDAPPolicyError struct {
	Code       uint16 `json:"code"`
	ResultName string `json:"result_name"`
	Message    string `json:"msg"`
}

func toLDAPPolicyError(err error) *LDAPPolicyError {
	if err == nil {
		return nil
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		name := ldap.LDAPResultCodeMap[ldapErr.ResultCode]
		if name == "" {
			name = "LDAP_ERROR"
		}
		return &LDAPPolicyError{
			Code:       ldapErr.ResultCode,
			ResultName: name,
			Message:    ldapErr.Error(),
		}
	}
	return &LDAPPolicyError{
		Code:       ldap.ErrorNetwork,
		ResultName: "PROVIDER_ERROR",
		Message:    err.Error(),
	}
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}

// HandleQueryLDAP implements the Query LDAP policy operation.
func (s *Server) HandleQueryLDAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, QueryLDAPResponse{Error: &LDAPPolicyError{Message: "POST required"}})
		return
	}

	var req QueryLDAPRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, QueryLDAPResponse{Error: toLDAPPolicyError(err)})
		return
	}

	pool, err := s.registry.Get(req.ProviderID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, QueryLDAPResponse{ProviderID: req.ProviderID, Error: toLDAPPolicyError(err)})
		return
	}
	cfg := pool.cfg

	protect := true
	if req.ProtectLDAPInjection != nil {
		protect = *req.ProtectLDAPInjection
	}

	baseDN := req.BaseDN
	if baseDN == "" {
		baseDN = cfg.DefaultBaseDN
	}
	baseDN = RenderDN(baseDN, req.FilterVariables, protect)
	rawFilter := strings.TrimSpace(req.Filter)
	if rawFilter == "" {
		rawFilter = fmt.Sprintf("(&(objectClass=%s)(%s=$[username]))", cfg.Profile.UserObjectClass, cfg.Profile.UserLoginAttr)
	}
	compiledFilter := RenderFilter(rawFilter, req.FilterVariables, protect)

	if isMockProvider(cfg) {
		entries, firstVars, firstDN := defaultMockDir.Search(baseDN, compiledFilter, req.Attributes, req.MultivalueMode)
		writeJSON(w, http.StatusOK, QueryLDAPResponse{
			Success:    len(entries) > 0,
			ProviderID: cfg.ID,
			Count:      len(entries),
			DN:         firstDN,
			Variables:  firstVars,
			Entries:    entries,
		})
		return
	}

	scope := ldap.ScopeWholeSubtree
	switch strings.ToUpper(strings.TrimSpace(req.Scope)) {
	case "BASE", "OBJECT":
		scope = ldap.ScopeBaseObject
	case "ONE", "ONELEVEL", "LEVEL":
		scope = ldap.ScopeSingleLevel
	case "SUB", "SUBTREE", "":
		scope = ldap.ScopeWholeSubtree
	}

	sizeLimit := req.MaxResults
	if sizeLimit <= 0 {
		sizeLimit = 100
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		sizeLimit,
		int(cfg.ReadTimeout.Seconds()),
		false,
		compiledFilter,
		req.Attributes,
		nil,
	)

	var res *ldap.SearchResult
	err = pool.WithServiceConn(func(conn *ldap.Conn) error {
		var sErr error
		res, sErr = conn.Search(searchReq)
		return sErr
	})
	if err != nil {
		status := http.StatusUnprocessableEntity
		if isNetworkError(err) {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, QueryLDAPResponse{ProviderID: cfg.ID, Error: toLDAPPolicyError(err)})
		return
	}

	entries := make([]QueryEntryItem, 0, len(res.Entries))
	var firstVars map[string]any
	var firstDN string

	for i, entry := range res.Entries {
		formatted := FormatAttributes(entry, req.Attributes, req.MultivalueMode)
		if i == 0 {
			firstVars = formatted
			firstDN = entry.DN
		}
		entries = append(entries, QueryEntryItem{
			DN:         entry.DN,
			Attributes: formatted,
		})
	}

	writeJSON(w, http.StatusOK, QueryLDAPResponse{
		Success:    len(entries) > 0,
		ProviderID: cfg.ID,
		Count:      len(entries),
		DN:         firstDN,
		Variables:  firstVars,
		Entries:    entries,
	})
}

// HandleWriteLDAP implements the Write LDAP policy operation.
func (s *Server) HandleWriteLDAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, WriteLDAPResponse{Error: &LDAPPolicyError{Message: "POST required"}})
		return
	}

	var req WriteLDAPRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, WriteLDAPResponse{Error: toLDAPPolicyError(err)})
		return
	}

	pool, err := s.registry.Get(req.ProviderID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, WriteLDAPResponse{ProviderID: req.ProviderID, Error: toLDAPPolicyError(err)})
		return
	}
	cfg := pool.cfg

	if isMockProvider(cfg) {
		protect := true
		if req.ProtectLDAPInjection != nil {
			protect = *req.ProtectLDAPInjection
		}
		targetDN, err := defaultMockDir.ExecuteWrite(req, cfg.WriteBaseDN, protect)
		if err != nil {
			status := http.StatusUnprocessableEntity
			var ldapErr *ldap.Error
			if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInsufficientAccessRights {
				status = http.StatusForbidden
			}
			writeJSON(w, status, WriteLDAPResponse{
				Success:    false,
				ProviderID: cfg.ID,
				DN:         targetDN,
				Error:      toLDAPPolicyError(err),
			})
			return
		}
		writeJSON(w, http.StatusOK, WriteLDAPResponse{
			Success:    true,
			ProviderID: cfg.ID,
			DN:         targetDN,
		})
		return
	}

	if strings.TrimSpace(req.LDIFTemplate) != "" {
		protect := true
		if req.ProtectLDAPInjection != nil {
			protect = *req.ProtectLDAPInjection
		}
		renderedLDIF := RenderDN(req.LDIFTemplate, req.Variables, protect)
		var targetDN string
		err := pool.WithServiceConn(func(conn *ldap.Conn) error {
			var lErr error
			targetDN, lErr = ExecuteLDIF(conn, renderedLDIF, cfg.WriteBaseDN)
			return lErr
		})
		if err != nil {
			status := http.StatusUnprocessableEntity
			var ldapErr *ldap.Error
			if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInsufficientAccessRights {
				status = http.StatusForbidden
			}
			writeJSON(w, status, WriteLDAPResponse{
				Success:    false,
				ProviderID: cfg.ID,
				DN:         targetDN,
				Error:      toLDAPPolicyError(err),
			})
			return
		}
		writeJSON(w, http.StatusOK, WriteLDAPResponse{
			Success:    true,
			ProviderID: cfg.ID,
			DN:         targetDN,
		})
		return
	}

	if err := ValidateWriteBaseDN(req.DN, cfg.WriteBaseDN); err != nil {
		writeJSON(w, http.StatusForbidden, WriteLDAPResponse{
			Success:    false,
			ProviderID: cfg.ID,
			DN:         req.DN,
			Error:      toLDAPPolicyError(err),
		})
		return
	}

	err = pool.WithServiceConn(func(conn *ldap.Conn) error {
		switch strings.ToUpper(strings.TrimSpace(req.Operation)) {
		case "ADD":
			addReq := ldap.NewAddRequest(req.DN, nil)
			for k, vals := range req.AddAttributes {
				addReq.Attribute(k, vals)
			}
			return conn.Add(addReq)
		case "MODIFY":
			modReq := ldap.NewModifyRequest(req.DN, nil)
			for _, m := range req.Modifications {
				switch strings.ToLower(m.Action) {
				case "add":
					modReq.Add(m.Attribute, m.Values)
				case "replace":
					modReq.Replace(m.Attribute, m.Values)
				case "delete":
					modReq.Delete(m.Attribute, m.Values)
				}
			}
			return conn.Modify(modReq)
		case "DELETE":
			return conn.Del(ldap.NewDelRequest(req.DN, nil))
		default:
			return fmt.Errorf("unsupported operation %q", req.Operation)
		}
	})

	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, WriteLDAPResponse{
			Success:    false,
			ProviderID: cfg.ID,
			DN:         req.DN,
			Error:      toLDAPPolicyError(err),
		})
		return
	}

	writeJSON(w, http.StatusOK, WriteLDAPResponse{
		Success:    true,
		ProviderID: cfg.ID,
		DN:         req.DN,
	})
}

// HandleAuthenticateLDAP implements the Authenticate User or Group policy operation.
func (s *Server) HandleAuthenticateLDAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, AuthenticateLDAPResponse{Error: &LDAPPolicyError{Message: "POST required"}})
		return
	}

	var req AuthenticateLDAPRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, AuthenticateLDAPResponse{Error: toLDAPPolicyError(err)})
		return
	}

	pool, err := s.registry.Get(req.ProviderID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, AuthenticateLDAPResponse{
			Authenticated: false,
			Authorized:    false,
			ProviderID:    req.ProviderID,
			Error:         toLDAPPolicyError(err),
		})
		return
	}
	cfg := pool.cfg

	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		writeJSON(w, http.StatusUnauthorized, AuthenticateLDAPResponse{
			Authenticated: false,
			Authorized:    false,
			ProviderID:    cfg.ID,
			Error:         &LDAPPolicyError{Code: ldap.LDAPResultInvalidCredentials, ResultName: "INVALID_CREDENTIALS", Message: "username and password are required"},
		})
		return
	}

	hasGroup := false
	for _, g := range req.RequireGroups {
		if strings.TrimSpace(g) != "" {
			hasGroup = true
			break
		}
	}
	if !hasGroup && cfg.DefaultRequireGroup != "" {
		req.RequireGroups = []string{cfg.DefaultRequireGroup}
	}

	if isMockProvider(cfg) {
		baseDN := req.BaseDN
		if baseDN == "" {
			baseDN = cfg.DefaultBaseDN
		}
		status, resp := defaultMockDir.Authenticate(req, cfg, baseDN)
		writeJSON(w, status, resp)
		return
	}

	var userDN string
	var userGroups []string
	var extractedVars map[string]any

	// Mode 1: Simple LDAP Identity Provider (Direct DN pattern bind using warm authConns pool)
	if cfg.SimpleBindPattern != "" && len(req.RequireGroups) == 0 && len(req.ReturnAttributes) == 0 {
		userDN = fmt.Sprintf(cfg.SimpleBindPattern, ldap.EscapeDN(req.Username))
		if err := pool.BindUser(userDN, req.Password); err != nil {
			status := http.StatusUnauthorized
			if isNetworkError(err) {
				status = http.StatusBadGateway
			}
			writeJSON(w, status, AuthenticateLDAPResponse{
				Authenticated: false,
				Authorized:    false,
				ProviderID:    cfg.ID,
				DN:            userDN,
				Error:         toLDAPPolicyError(err),
			})
			return
		}

		authorized := checkAllowedUsers(req.Username, userDN, req.RequireUsers)
		status := http.StatusOK
		if !authorized {
			status = http.StatusForbidden
		}
		writeJSON(w, status, AuthenticateLDAPResponse{
			Authenticated: true,
			Authorized:    authorized,
			ProviderID:    cfg.ID,
			DN:            userDN,
		})
		return
	}

	// Mode 2: Search User DN & Attributes on Warm Service Pool -> Verify Password on Warm Auth Pool
	baseDN := req.BaseDN
	if baseDN == "" {
		baseDN = cfg.DefaultBaseDN
	}

	filter := req.UserSearchFilter
	if filter == "" {
		filter = fmt.Sprintf("(&(objectClass=%s)(%s=%s))",
			cfg.Profile.UserObjectClass,
			cfg.Profile.UserLoginAttr,
			ldap.EscapeFilter(req.Username))
	} else {
		filter = RenderFilter(filter, map[string]string{"username": req.Username}, true)
	}

	attrsToFetch := append([]string{cfg.Profile.MemberOfAttr}, req.ReturnAttributes...)
	var entry *ldap.Entry
	err = pool.WithServiceConn(func(searchConn *ldap.Conn) error {
		sr, sErr := searchConn.Search(ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1,
			int(cfg.ReadTimeout.Seconds()),
			false,
			filter,
			attrsToFetch,
			nil,
		))
		if sErr != nil {
			return sErr
		}
		if len(sr.Entries) == 0 {
			return nil
		}
		entry = sr.Entries[0]
		userDN = entry.DN
		userGroups = entry.GetAttributeValues(cfg.Profile.MemberOfAttr)
		if len(userGroups) == 0 {
			groupSearchFilter := fmt.Sprintf("(%s=%s)", cfg.Profile.GroupMemberAttr, ldap.EscapeFilter(userDN))
			gsr, gErr := searchConn.Search(ldap.NewSearchRequest(
				baseDN,
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				50,
				int(cfg.ReadTimeout.Seconds()),
				false,
				groupSearchFilter,
				[]string{"dn"},
				nil,
			))
			if gErr == nil {
				for _, ge := range gsr.Entries {
					userGroups = append(userGroups, ge.DN)
				}
			}
		}
		return nil
	})
	if err != nil {
		status := http.StatusUnprocessableEntity
		if isNetworkError(err) {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, AuthenticateLDAPResponse{ProviderID: cfg.ID, Error: toLDAPPolicyError(err)})
		return
	}
	if entry == nil {
		writeJSON(w, http.StatusUnauthorized, AuthenticateLDAPResponse{
			Authenticated: false,
			Authorized:    false,
			ProviderID:    cfg.ID,
			Error:         &LDAPPolicyError{Code: ldap.LDAPResultInvalidCredentials, ResultName: "USER_NOT_FOUND", Message: "user not found in directory"},
		})
		return
	}

	extractedVars = FormatAttributes(entry, req.ReturnAttributes, req.MultivalueMode)
	if len(userGroups) > 0 {
		if strings.ToUpper(strings.TrimSpace(req.MultivalueMode)) == "ARRAY" {
			extractedVars["memberOf"] = userGroups
		} else if strings.ToUpper(strings.TrimSpace(req.MultivalueMode)) == "JOIN_COMMA" {
			extractedVars["memberOf"] = strings.Join(userGroups, ",")
		} else if extractedVars["memberOf"] == nil || extractedVars["memberOf"] == "" {
			extractedVars["memberOf"] = userGroups[0]
		}
	}

	// Verify user password via the warm Auth Pool (reusing established TCP+TLS sockets per RFC 4511 §4.2.1)
	if err := pool.BindUser(userDN, req.Password); err != nil {
		status := http.StatusUnauthorized
		if isNetworkError(err) {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, AuthenticateLDAPResponse{
			Authenticated: false,
			Authorized:    false,
			ProviderID:    cfg.ID,
			DN:            userDN,
			Error:         toLDAPPolicyError(err),
		})
		return
	}

	authorized := checkAllowedUsers(req.Username, userDN, req.RequireUsers)
	if authorized && len(req.RequireGroups) > 0 {
		_ = pool.WithServiceConn(func(searchConn *ldap.Conn) error {
			authorized = verifyGroupMembership(searchConn, cfg, baseDN, userDN, userGroups, req.RequireGroups, req.ResolveNestedAD)
			return nil
		})
	}

	status := http.StatusOK
	var authErr *LDAPPolicyError
	if !authorized {
		status = http.StatusForbidden
		authErr = &LDAPPolicyError{
			Code:       ldap.LDAPResultInsufficientAccessRights,
			ResultName: "INSUFFICIENT_ACCESS_RIGHTS",
			Message:    "user is authenticated in LDAP directory but does not belong to required group",
		}
	}

	writeJSON(w, status, AuthenticateLDAPResponse{
		Authenticated: true,
		Authorized:    authorized,
		ProviderID:    cfg.ID,
		DN:            userDN,
		Groups:        userGroups,
		Variables:     extractedVars,
		Error:         authErr,
	})
}

func checkAllowedUsers(username, userDN string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(candidate, username) || strings.EqualFold(candidate, userDN) {
			return true
		}
	}
	return false
}

func verifyGroupMembership(conn *ldap.Conn, cfg *Config, baseDN, userDN string, directGroups, requiredGroups []string, resolveNestedAD bool) bool {
	hasNonEmptyReq := false
	for _, reqGroup := range requiredGroups {
		reqGroup = strings.TrimSpace(reqGroup)
		if reqGroup == "" {
			continue
		}
		hasNonEmptyReq = true
		for _, dg := range directGroups {
			if strings.EqualFold(dg, reqGroup) ||
				strings.HasPrefix(strings.ToLower(dg), "cn="+strings.ToLower(reqGroup)+",") ||
				strings.HasPrefix(strings.ToLower(dg), "ou="+strings.ToLower(reqGroup)+",") {
				return true
			}
		}
	}
	if !hasNonEmptyReq {
		return true
	}

	for _, reqGroup := range requiredGroups {
		reqGroup = strings.TrimSpace(reqGroup)
		if reqGroup == "" {
			continue
		}
		if strings.Contains(reqGroup, "=") {
			memberFilter := fmt.Sprintf("(%s=%s)", cfg.Profile.GroupMemberAttr, ldap.EscapeFilter(userDN))
			sr, err := conn.Search(ldap.NewSearchRequest(
				reqGroup,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				1,
				int(cfg.ReadTimeout.Seconds()),
				false,
				memberFilter,
				[]string{"dn"},
				nil,
			))
			if err == nil && len(sr.Entries) > 0 {
				return true
			}
		}

		var groupFilter string
		if resolveNestedAD && cfg.Profile.SupportsADInChain {
			groupFilter = fmt.Sprintf("(&(objectClass=%s)(%s:1.2.840.113556.1.4.1941:=%s)(|(distinguishedName=%s)(cn=%s)(ou=%s)))",
				cfg.Profile.GroupObjectClass,
				cfg.Profile.GroupMemberAttr,
				ldap.EscapeFilter(userDN),
				ldap.EscapeFilter(reqGroup),
				ldap.EscapeFilter(reqGroup),
				ldap.EscapeFilter(reqGroup))
		} else {
			groupFilter = fmt.Sprintf("(&(objectClass=%s)(%s=%s)(|(cn=%s)(ou=%s)(distinguishedName=%s)))",
				cfg.Profile.GroupObjectClass,
				cfg.Profile.GroupMemberAttr,
				ldap.EscapeFilter(userDN),
				ldap.EscapeFilter(reqGroup),
				ldap.EscapeFilter(reqGroup),
				ldap.EscapeFilter(reqGroup))
		}

		sr, err := conn.Search(ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1,
			int(cfg.ReadTimeout.Seconds()),
			false,
			groupFilter,
			[]string{"dn"},
			nil,
		))
		if err == nil && len(sr.Entries) > 0 {
			return true
		}
	}
	return false
}

func (s *Server) HandleProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"providers": s.registry.Summary(),
		})
	case http.MethodPost, http.MethodPut:
		var pJSON ProviderConfigJSON
		if err := decodeJSONBody(w, r, &pJSON); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false,
				"error":   fmt.Sprintf("invalid provider JSON: %v", err),
			})
			return
		}
		cfg, err := s.registry.Upsert(pJSON)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"success":     false,
				"provider_id": pJSON.ID,
				"error":       err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success":               true,
			"status":                "registered_and_warmed",
			"provider_id":           cfg.ID,
			"profile":               cfg.Profile.Name,
			"user_login_attr":       cfg.Profile.UserLoginAttr,
			"urls":                  cfg.LDAPURLs,
			"base_dn":               cfg.DefaultBaseDN,
			"write_base_dn":         cfg.WriteBaseDN,
			"default_require_group": cfg.DefaultRequireGroup,
		})
	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/v1/ldap/providers")
		id = strings.Trim(id, "/")
		if id == "" {
			id = r.URL.Query().Get("id")
		}
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "provider id required"})
			return
		}
		deleted := s.registry.Delete(id)
		if !deleted {
			writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "provider_id": id, "error": "provider not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": "deleted", "provider_id": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "GET, POST, PUT, or DELETE required"})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	registry, err := LoadProviderRegistry()
	if err != nil {
		slog.Error("Failed to initialize LDAP Provider Registry", "error", err)
		os.Exit(1)
	}
	defer registry.CloseAll()

	srv := &Server{
		registry: registry,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ldap/query", srv.HandleQueryLDAP)
	mux.HandleFunc("/v1/ldap/write", srv.HandleWriteLDAP)
	mux.HandleFunc("/v1/ldap/authenticate", srv.HandleAuthenticateLDAP)
	mux.HandleFunc("/v1/ldap/providers", srv.HandleProviders)
	mux.HandleFunc("/v1/ldap/providers/", srv.HandleProviders)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	port := envOrDefault("PORT", "8080")
	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("Multi-Provider LDAP Policy Connector listening",
			"port", port,
			"provider_count", len(registry.pools))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server terminated", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down server gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

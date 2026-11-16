package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var placeholderRegex = regexp.MustCompile(`(?:\$\{|\$\[)([a-zA-Z0-9_.-]+)(?:\}|\])`)

// RenderFilter substitutes ${var} or $[var] placeholders in an LDAP search filter.
// When protectInjection is true (LDAP injection protection enabled),
// every substituted value is escaped per RFC 4515 / RFC 2254 without secondary regex allocations.
func RenderFilter(template string, vars map[string]string, protectInjection bool) string {
	if len(vars) == 0 || !strings.Contains(template, "$") {
		return template
	}
	return placeholderRegex.ReplaceAllStringFunc(template, func(match string) string {
		if len(match) <= 3 {
			return match
		}
		key := match[2 : len(match)-1]
		val, exists := vars[key]
		if !exists {
			return ""
		}
		if protectInjection {
			return ldap.EscapeFilter(val)
		}
		return val
	})
}

// RenderDN substitutes ${var} or $[var] placeholders in a Distinguished Name,
// escaping dynamic attribute values per RFC 4514 so DN injection cannot occur.
func RenderDN(template string, vars map[string]string, protectInjection bool) string {
	if len(vars) == 0 || !strings.Contains(template, "$") {
		return template
	}
	return placeholderRegex.ReplaceAllStringFunc(template, func(match string) string {
		if len(match) <= 3 {
			return match
		}
		key := match[2 : len(match)-1]
		val, exists := vars[key]
		if !exists {
			return ""
		}
		if protectInjection {
			return ldap.EscapeDN(val)
		}
		return val
	})
}

// ValidateWriteBaseDN enforces the provider's "Write Base DN" security boundary.
// It parses both targetDN and writeBaseDN using RFC 4514 AST parsing to prevent DN traversal.
func ValidateWriteBaseDN(targetDN, writeBaseDN string) error {
	if strings.TrimSpace(writeBaseDN) == "" {
		return errors.New("write operations are disabled: write_base_dn is not configured for this provider")
	}
	parsedTarget, err := ldap.ParseDN(targetDN)
	if err != nil {
		return fmt.Errorf("invalid target DN %q: %w", targetDN, err)
	}
	parsedBase, err := ldap.ParseDN(writeBaseDN)
	if err != nil {
		return fmt.Errorf("invalid write_base_dn %q: %w", writeBaseDN, err)
	}
	if !parsedBase.AncestorOf(parsedTarget) && !parsedBase.Equal(parsedTarget) {
		return fmt.Errorf("target DN %q is outside permitted Write Base DN %q", targetDN, writeBaseDN)
	}
	return nil
}

// FormatAttributes shapes LDAP entry attributes according to the configured multivalue handling mode:
// - "FIRST": returns only the first attribute value as a string
// - "JOIN_COMMA": concatenates all values with commas into a single string
// - "ARRAY": returns the full slice of strings (multivalued context variable)
func FormatAttributes(entry *ldap.Entry, requestedAttrs []string, multivalueMode string) map[string]any {
	mode := strings.ToUpper(strings.TrimSpace(multivalueMode))
	if mode == "" {
		mode = "FIRST"
	}

	result := make(map[string]any, len(entry.Attributes))
	for _, attr := range entry.Attributes {
		if len(attr.Values) == 0 {
			continue
		}
		switch mode {
		case "JOIN_COMMA", "CSV":
			result[attr.Name] = strings.Join(attr.Values, ",")
		case "ARRAY", "MULTIVALUE":
			result[attr.Name] = attr.Values
		default: // "FIRST"
			result[attr.Name] = attr.Values[0]
		}
	}

	for _, reqAttr := range requestedAttrs {
		if _, found := result[reqAttr]; !found {
			for _, attr := range entry.Attributes {
				if strings.EqualFold(attr.Name, reqAttr) && len(attr.Values) > 0 {
					switch mode {
					case "JOIN_COMMA", "CSV":
						result[reqAttr] = strings.Join(attr.Values, ",")
					case "ARRAY", "MULTIVALUE":
						result[reqAttr] = attr.Values
					default:
						result[reqAttr] = attr.Values[0]
					}
					break
				}
			}
			if _, stillMissing := result[reqAttr]; !stillMissing {
				result[reqAttr] = ""
			}
		}
	}
	return result
}

// ExecuteLDIF parses and executes an RFC 2849 LDIF payload (add, modify, delete)
// while enforcing the Write Base DN restriction on every record.
func ExecuteLDIF(conn *ldap.Conn, ldifText string, writeBaseDN string) (string, error) {
	unfolded := unfoldLDIFLines(ldifText)
	if len(unfolded) == 0 {
		return "", errors.New("empty LDIF payload")
	}

	var targetDN string
	var changeType string
	idx := 0

	for idx < len(unfolded) {
		k, v, ok := parseLDIFLine(unfolded[idx])
		idx++
		if !ok {
			continue
		}
		if strings.EqualFold(k, "version") {
			continue
		}
		if strings.EqualFold(k, "dn") {
			targetDN = v
			break
		}
	}

	if targetDN == "" {
		return "", errors.New("LDIF missing 'dn:' header")
	}

	if err := ValidateWriteBaseDN(targetDN, writeBaseDN); err != nil {
		return targetDN, &ldap.Error{
			ResultCode: ldap.LDAPResultInsufficientAccessRights,
			Err:        err,
		}
	}

	if idx < len(unfolded) {
		k, v, ok := parseLDIFLine(unfolded[idx])
		if ok && strings.EqualFold(k, "changetype") {
			changeType = strings.ToLower(strings.TrimSpace(v))
			idx++
		} else {
			changeType = "add"
		}
	}

	switch changeType {
	case "add":
		addReq := ldap.NewAddRequest(targetDN, nil)
		attrMap := make(map[string][]string)
		for ; idx < len(unfolded); idx++ {
			k, v, ok := parseLDIFLine(unfolded[idx])
			if !ok || k == "-" {
				continue
			}
			attrMap[k] = append(attrMap[k], v)
		}
		for attrName, vals := range attrMap {
			addReq.Attribute(attrName, vals)
		}
		return targetDN, conn.Add(addReq)

	case "delete":
		delReq := ldap.NewDelRequest(targetDN, nil)
		return targetDN, conn.Del(delReq)

	case "modify":
		modReq := ldap.NewModifyRequest(targetDN, nil)
		for idx < len(unfolded) {
			opKey, attrName, ok := parseLDIFLine(unfolded[idx])
			idx++
			if !ok || opKey == "-" {
				continue
			}
			var vals []string
			for idx < len(unfolded) {
				line := strings.TrimSpace(unfolded[idx])
				idx++
				if line == "-" {
					break
				}
				_, val, ok := parseLDIFLine(line)
				if ok {
					vals = append(vals, val)
				}
			}
			switch strings.ToLower(opKey) {
			case "add":
				modReq.Add(attrName, vals)
			case "replace":
				modReq.Replace(attrName, vals)
			case "delete":
				modReq.Delete(attrName, vals)
			default:
				return targetDN, fmt.Errorf("unsupported LDIF modify operation %q", opKey)
			}
		}
		return targetDN, conn.Modify(modReq)

	default:
		return targetDN, fmt.Errorf("unsupported LDIF changetype %q", changeType)
	}
}

func unfoldLDIFLines(ldifText string) []string {
	scanner := bufio.NewScanner(strings.NewReader(ldifText))
	var lines []string
	for scanner.Scan() {
		raw := scanner.Text()
		if strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, " ") && len(lines) > 0 {
			lines[len(lines)-1] += strings.TrimPrefix(raw, " ")
			continue
		}
		if strings.TrimSpace(raw) == "" {
			continue
		}
		lines = append(lines, raw)
	}
	return lines
}

func parseLDIFLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "-" {
		return "-", "", true
	}
	if strings.Contains(trimmed, "::") {
		parts := strings.SplitN(trimmed, "::", 2)
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil {
			return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
		}
		return strings.TrimSpace(parts[0]), string(decoded), true
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

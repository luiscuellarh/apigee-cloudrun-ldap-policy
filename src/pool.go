package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const defaultMaxIdleAge = 90 * time.Second

// DirectoryProfile defines standard enterprise LDAP Identity Provider schema templates.
type DirectoryProfile struct {
	Name              string `json:"name"`
	UserObjectClass   string `json:"user_object_class"`
	UserLoginAttr     string `json:"user_login_attr"`
	GroupObjectClass  string `json:"group_object_class"`
	GroupMemberAttr   string `json:"group_member_attr"`
	MemberOfAttr      string `json:"member_of_attr"`
	SupportsADInChain bool   `json:"supports_ad_in_chain"`
}

var Profiles = map[string]DirectoryProfile{
	"MSAD": {
		Name:              "MSAD",
		UserObjectClass:   "user",
		UserLoginAttr:     "sAMAccountName",
		GroupObjectClass:  "group",
		GroupMemberAttr:   "member",
		MemberOfAttr:      "memberOf",
		SupportsADInChain: true,
	},
	"GENERIC": {
		Name:              "GENERIC",
		UserObjectClass:   "inetOrgPerson",
		UserLoginAttr:     "uid",
		GroupObjectClass:  "groupOfNames",
		GroupMemberAttr:   "member",
		MemberOfAttr:      "memberOf",
		SupportsADInChain: false,
	},
	"ORACLE": {
		Name:              "ORACLE",
		UserObjectClass:   "inetOrgPerson",
		UserLoginAttr:     "cn",
		GroupObjectClass:  "groupOfUniqueNames",
		GroupMemberAttr:   "uniqueMember",
		MemberOfAttr:      "memberOf",
		SupportsADInChain: false,
	},
	"TIVOLI": {
		Name:              "TIVOLI",
		UserObjectClass:   "ePerson",
		UserLoginAttr:     "uid",
		GroupObjectClass:  "groupOfNames",
		GroupMemberAttr:   "member",
		MemberOfAttr:      "ibm-allGroups",
		SupportsADInChain: false,
	},
}

// ProviderConfigJSON defines a single LDAP Identity Provider in JSON configuration.
type ProviderConfigJSON struct {
	ID                  string   `json:"id"`
	URLs                []string `json:"urls"`
	Profile             string   `json:"profile"` // "MSAD", "GENERIC", "ORACLE", "TIVOLI"
	UserLoginAttr       string   `json:"user_login_attr,omitempty"`
	BaseDN              string   `json:"base_dn"`
	WriteBaseDN         string   `json:"write_base_dn,omitempty"`
	DefaultRequireGroup string   `json:"default_require_group,omitempty"`
	BindDN              string   `json:"bind_dn,omitempty"`
	BindPassword        string   `json:"bind_password,omitempty"`      // Direct value or "${ENV_VAR_NAME}"
	BindPasswordEnv     string   `json:"bind_password_env,omitempty"`  // Name of Secret Manager env var holding password
	SimpleBindPattern   string   `json:"simple_bind_pattern,omitempty"` // e.g., "uid=%s,ou=People,dc=example,dc=com"
	ConnTimeout         string   `json:"conn_timeout,omitempty"`        // e.g., "3s"
	ReadTimeout         string   `json:"read_timeout,omitempty"`        // e.g., "5s"
	BlacklistDuration   string   `json:"blacklist_duration,omitempty"`  // e.g., "30s"
	PoolMaxIdle         int      `json:"pool_max_idle,omitempty"`
	UseStartTLS         bool     `json:"use_starttls,omitempty"`
	CACertPEMEnv        string   `json:"ca_cert_pem_env,omitempty"`
	ClientCertPEMEnv    string   `json:"client_cert_pem_env,omitempty"`
	ClientKeyPEMEnv     string   `json:"client_key_pem_env,omitempty"`
}

// MultiProviderFile is the top-level JSON structure for configuring multiple LDAP Identity Providers.
type MultiProviderFile struct {
	Providers []ProviderConfigJSON `json:"providers"`
}

// Config holds the runtime configuration for one LDAP Identity Provider.
type Config struct {
	ID                  string
	LDAPURLs            []string
	DefaultBaseDN       string
	WriteBaseDN         string
	DefaultRequireGroup string
	BindDN              string
	BindPassword        string
	SimpleBindPattern   string
	Profile             DirectoryProfile
	ConnTimeout         time.Duration
	ReadTimeout         time.Duration
	BlacklistDuration   time.Duration
	PoolMaxIdle         int
	UseStartTLS         bool
	TLSConfig           *tls.Config
}

// ProviderRegistry manages multiple named LDAP Identity Providers, each with an isolated LDAPPool.
type ProviderRegistry struct {
	mu    sync.RWMutex
	pools map[string]*LDAPPool
}

func LoadProviderRegistry() (*ProviderRegistry, error) {
	rawJSON := os.Getenv("LDAP_PROVIDERS_JSON")
	if configPath := os.Getenv("LDAP_PROVIDERS_CONFIG_PATH"); configPath != "" && rawJSON == "" {
		b, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading LDAP_PROVIDERS_CONFIG_PATH (%s): %w", configPath, err)
		}
		rawJSON = string(b)
	}

	reg := &ProviderRegistry{
		pools: make(map[string]*LDAPPool),
	}

	if strings.TrimSpace(rawJSON) != "" {
		var mp MultiProviderFile
		if err := json.Unmarshal([]byte(rawJSON), &mp); err != nil {
			return nil, fmt.Errorf("parsing multi-provider JSON config: %w", err)
		}
		for _, pJSON := range mp.Providers {
			cfg, err := buildProviderConfig(pJSON)
			if err != nil {
				return nil, fmt.Errorf("provider %q: %w", pJSON.ID, err)
			}
			reg.pools[cfg.ID] = NewLDAPPool(cfg)
		}
	}
	return reg, nil
}

// Get returns the LDAPPool for the explicitly requested providerID.
func (r *ProviderRegistry) Get(providerID string) (*LDAPPool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id := strings.TrimSpace(providerID)
	if id == "" {
		return nil, errors.New("provider_id is required (no global default provider is configured)")
	}
	pool, exists := r.pools[id]
	if !exists {
		return nil, fmt.Errorf("unknown LDAP identity provider %q", id)
	}
	return pool, nil
}

// Upsert validates, pre-warms, and registers or updates an LDAP Identity Provider in memory,
// cleanly closing any previous connection pool for that provider ID.
func (r *ProviderRegistry) Upsert(pJSON ProviderConfigJSON) (*Config, error) {
	cfg, err := buildProviderConfig(pJSON)
	if err != nil {
		return nil, err
	}
	newPool := NewLDAPPool(cfg)

	if !isMockProvider(cfg) {
		if err := newPool.WithServiceConn(func(_ *ldap.Conn) error { return nil }); err != nil {
			newPool.Close()
			return nil, fmt.Errorf("failed to bind/connect to LDAP provider %q: %w", cfg.ID, err)
		}
	}

	r.mu.Lock()
	oldPool := r.pools[cfg.ID]
	r.pools[cfg.ID] = newPool
	r.mu.Unlock()

	if oldPool != nil {
		oldPool.Close()
	}
	return cfg, nil
}

// Delete removes an LDAP Identity Provider from the in-memory registry and closes its idle sockets.
func (r *ProviderRegistry) Delete(providerID string) bool {
	id := strings.TrimSpace(providerID)
	r.mu.Lock()
	oldPool, exists := r.pools[id]
	if exists {
		delete(r.pools, id)
	}
	r.mu.Unlock()

	if oldPool != nil {
		oldPool.Close()
	}
	return exists
}

// CloseAll closes all idle LDAP connections across all registered providers during graceful shutdown.
func (r *ProviderRegistry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pool := range r.pools {
		pool.Close()
	}
}

func (r *ProviderRegistry) Summary() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]map[string]any, 0, len(r.pools))
	for id, pool := range r.pools {
		out = append(out, map[string]any{
			"provider_id":           id,
			"profile":               pool.cfg.Profile.Name,
			"user_login_attr":       pool.cfg.Profile.UserLoginAttr,
			"urls":                  pool.cfg.LDAPURLs,
			"base_dn":               pool.cfg.DefaultBaseDN,
			"write_base_dn":         pool.cfg.WriteBaseDN,
			"default_require_group": pool.cfg.DefaultRequireGroup,
			"simple_ldap_mode":      pool.cfg.SimpleBindPattern != "",
		})
	}
	return out
}

func buildProviderConfig(p ProviderConfigJSON) (*Config, error) {
	if strings.TrimSpace(p.ID) == "" {
		return nil, errors.New("provider 'id' is required")
	}
	if len(p.URLs) == 0 {
		return nil, errors.New("provider 'urls' must contain at least one LDAP URL")
	}

	profileName := strings.ToUpper(strings.TrimSpace(p.Profile))
	if profileName == "" {
		profileName = "MSAD"
	}
	profile, ok := Profiles[profileName]
	if !ok {
		profile = Profiles["GENERIC"]
	}
	if p.UserLoginAttr != "" {
		profile.UserLoginAttr = p.UserLoginAttr
	}

	bindPass := p.BindPassword
	if p.BindPasswordEnv != "" {
		bindPass = os.Getenv(p.BindPasswordEnv)
	} else if strings.HasPrefix(bindPass, "${") && strings.HasSuffix(bindPass, "}") {
		envKey := strings.TrimSuffix(strings.TrimPrefix(bindPass, "${"), "}")
		bindPass = os.Getenv(envKey)
	}

	connTimeout, _ := time.ParseDuration(defaultStr(p.ConnTimeout, "3s"))
	readTimeout, _ := time.ParseDuration(defaultStr(p.ReadTimeout, "5s"))
	blacklistDur, _ := time.ParseDuration(defaultStr(p.BlacklistDuration, "30s"))
	maxIdle := p.PoolMaxIdle
	if maxIdle <= 0 {
		maxIdle = 16
	}

	caPEM := os.Getenv(defaultStr(p.CACertPEMEnv, "LDAP_CA_CERT_PEM"))
	clientCertPEM := os.Getenv(defaultStr(p.ClientCertPEMEnv, "LDAP_CLIENT_CERT_PEM"))
	clientKeyPEM := os.Getenv(defaultStr(p.ClientKeyPEMEnv, "LDAP_CLIENT_KEY_PEM"))

	tlsCfg, err := buildTLSConfigFromPEM(caPEM, clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, err
	}

	return &Config{
		ID:                  p.ID,
		LDAPURLs:            p.URLs,
		DefaultBaseDN:       p.BaseDN,
		WriteBaseDN:         p.WriteBaseDN,
		DefaultRequireGroup: p.DefaultRequireGroup,
		BindDN:              p.BindDN,
		BindPassword:        bindPass,
		SimpleBindPattern:   p.SimpleBindPattern,
		Profile:             profile,
		ConnTimeout:         connTimeout,
		ReadTimeout:         readTimeout,
		BlacklistDuration:   blacklistDur,
		PoolMaxIdle:         maxIdle,
		UseStartTLS:         p.UseStartTLS,
		TLSConfig:           tlsCfg,
	}, nil
}

func buildTLSConfigFromPEM(caPEM, clientCertPEM, clientKeyPEM string) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if strings.TrimSpace(caPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("failed to parse CA certificate PEM")
		}
		tlsCfg.RootCAs = pool
	}
	if strings.TrimSpace(clientCertPEM) != "" && strings.TrimSpace(clientKeyPEM) != "" {
		cert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to load mTLS client certificate/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

type pooledConn struct {
	conn     *ldap.Conn
	lastUsed time.Time
}

// LDAPPool manages two warm connection pools per provider:
//  1. serviceConns: Pre-bound with BindDN for Search and Write operations.
//  2. authConns:    Dedicated pool for User Bind verification (RFC 4511 §4.2.1 sequential binds).
type LDAPPool struct {
	cfg          *Config
	serviceConns chan pooledConn
	authConns    chan pooledConn
	mu           sync.RWMutex
	blacklist    map[string]time.Time
}

func NewLDAPPool(cfg *Config) *LDAPPool {
	return &LDAPPool{
		cfg:          cfg,
		serviceConns: make(chan pooledConn, cfg.PoolMaxIdle),
		authConns:    make(chan pooledConn, cfg.PoolMaxIdle),
		blacklist:    make(map[string]time.Time),
	}
}

// WithServiceConn executes fn using a pooled service connection and automatically retries once
// on a fresh connection if a stale idle socket encounters a network/EOF error.
func (p *LDAPPool) WithServiceConn(fn func(*ldap.Conn) error) error {
	conn, reused, err := p.acquireService()
	if err != nil {
		return err
	}
	err = fn(conn)
	if err != nil && reused && isNetworkError(err) {
		_ = conn.Close()
		conn, _, dialErr := p.acquireServiceFresh()
		if dialErr != nil {
			return dialErr
		}
		err = fn(conn)
	}
	if err != nil && isNetworkError(err) {
		_ = conn.Close()
		return err
	}
	p.releaseService(conn)
	return err
}

// BindUser verifies a user's DN and password using a warm pooled connection (RFC 4511 §4.2.1),
// avoiding a full TCP+TLS handshake on every authentication request.
func (p *LDAPPool) BindUser(userDN, password string) error {
	conn, reused, err := p.acquireAuth()
	if err != nil {
		return err
	}
	err = conn.Bind(userDN, password)
	if err != nil && reused && isNetworkError(err) {
		_ = conn.Close()
		conn, err = p.DialUnbound()
		if err != nil {
			return err
		}
		err = conn.Bind(userDN, password)
	}
	if err != nil && isNetworkError(err) {
		_ = conn.Close()
		return err
	}
	p.releaseAuth(conn)
	return err
}

// Close drains both connection channels and closes all underlying TCP/TLS sockets.
func (p *LDAPPool) Close() {
	for {
		select {
		case pc := <-p.serviceConns:
			if pc.conn != nil {
				_ = pc.conn.Close()
			}
		default:
			goto drainAuth
		}
	}
drainAuth:
	for {
		select {
		case pc := <-p.authConns:
			if pc.conn != nil {
				_ = pc.conn.Close()
			}
		default:
			return
		}
	}
}

func (p *LDAPPool) acquireService() (*ldap.Conn, bool, error) {
	now := time.Now()
	for {
		select {
		case pc := <-p.serviceConns:
			if pc.conn == nil || pc.conn.IsClosing() {
				continue
			}
			if now.Sub(pc.lastUsed) > defaultMaxIdleAge {
				_ = pc.conn.Close()
				continue
			}
			return pc.conn, true, nil
		default:
			return p.acquireServiceFresh()
		}
	}
}

func (p *LDAPPool) acquireServiceFresh() (*ldap.Conn, bool, error) {
	conn, err := p.dialAndServiceBind()
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}

func (p *LDAPPool) releaseService(conn *ldap.Conn) {
	if conn == nil || conn.IsClosing() {
		return
	}
	select {
	case p.serviceConns <- pooledConn{conn: conn, lastUsed: time.Now()}:
	default:
		_ = conn.Close()
	}
}

func (p *LDAPPool) acquireAuth() (*ldap.Conn, bool, error) {
	now := time.Now()
	for {
		select {
		case pc := <-p.authConns:
			if pc.conn == nil || pc.conn.IsClosing() {
				continue
			}
			if now.Sub(pc.lastUsed) > defaultMaxIdleAge {
				_ = pc.conn.Close()
				continue
			}
			return pc.conn, true, nil
		default:
			conn, err := p.DialUnbound()
			if err != nil {
				return nil, false, err
			}
			return conn, false, nil
		}
	}
}

func (p *LDAPPool) releaseAuth(conn *ldap.Conn) {
	if conn == nil || conn.IsClosing() {
		return
	}
	select {
	case p.authConns <- pooledConn{conn: conn, lastUsed: time.Now()}:
	default:
		_ = conn.Close()
	}
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection closed")
}

func (p *LDAPPool) DialUnbound() (*ldap.Conn, error) {
	var lastErr error
	now := time.Now()

	for _, rawURL := range p.cfg.LDAPURLs {
		p.mu.RLock()
		until, blacklisted := p.blacklist[rawURL]
		p.mu.RUnlock()
		if blacklisted && now.Before(until) {
			continue
		}

		conn, err := p.dialSingle(rawURL)
		if err != nil {
			lastErr = err
			p.mu.Lock()
			p.blacklist[rawURL] = time.Now().Add(p.cfg.BlacklistDuration)
			p.mu.Unlock()
			slog.Warn("LDAP node unreachable, temporarily blacklisted",
				"provider_id", p.cfg.ID,
				"url", rawURL,
				"error", err)
			continue
		}
		return conn, nil
	}

	if lastErr == nil {
		for _, rawURL := range p.cfg.LDAPURLs {
			conn, err := p.dialSingle(rawURL)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
	}
	return nil, fmt.Errorf("all LDAP nodes failed for provider %q: %w", p.cfg.ID, lastErr)
}

func (p *LDAPPool) dialAndServiceBind() (*ldap.Conn, error) {
	conn, err := p.DialUnbound()
	if err != nil {
		return nil, err
	}
	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("service bind failed for %q: %w", p.cfg.BindDN, err)
		}
	}
	return conn, nil
}

func (p *LDAPPool) dialSingle(rawURL string) (*ldap.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:   p.cfg.ConnTimeout,
		KeepAlive: 30 * time.Second,
	}
	var dialOpts []ldap.DialOpt
	dialOpts = append(dialOpts, ldap.DialWithDialer(dialer))

	if strings.EqualFold(u.Scheme, "ldaps") {
		tlsCopy := p.cfg.TLSConfig.Clone()
		tlsCopy.ServerName = u.Hostname()
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(tlsCopy))
	}

	conn, err := ldap.DialURL(rawURL, dialOpts...)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(p.cfg.ReadTimeout)

	if p.cfg.UseStartTLS && strings.EqualFold(u.Scheme, "ldap") {
		tlsCopy := p.cfg.TLSConfig.Clone()
		tlsCopy.ServerName = u.Hostname()
		if err := conn.StartTLS(tlsCopy); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func defaultStr(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

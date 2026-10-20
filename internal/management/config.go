package management

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// Config contains management service settings. Secrets stay in this process.
type Config struct {
	Listen    string
	PublicURL string
	// AdditionalOrigins are further exact HTTPS origins the console is served
	// at, such as its in-network address. Requests are checked against the
	// origin their Host names, never across origins.
	AdditionalOrigins []string
	// ControlURL is the coordinator's public origin, shown in join commands.
	// Empty means the origin of the brokered sign-in issuer (…/identity).
	ControlURL       string
	AdminToken       string
	HeadscaleURL     string
	HeadscaleAPIKey  string
	HeadscaleCAFile  string
	DataDir          string
	AllowHTTP        bool
	AuthMode         string
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCLabel        string
	TLSCertFile      string
	TLSKeyFile       string
	// GatewayTag and GatewayDir turn on the console's Gateway page: the tag
	// of the network's gateway device, and the directory where this service
	// keeps its settings and the files the device and the host read.
	GatewayTag string
	GatewayDir string
}

func ConfigFromEnv() (Config, error) {
	adminToken, err := secretFromEnv("COVEE_ADMIN_TOKEN")
	if err != nil {
		return Config{}, err
	}
	apiKey, err := secretFromEnv("COVEE_HEADSCALE_API_KEY")
	if err != nil {
		return Config{}, err
	}
	oidcSecret, err := secretFromEnv("COVEE_OIDC_CLIENT_SECRET")
	if err != nil {
		return Config{}, err
	}
	c := Config{Listen: envDefault("COVEE_LISTEN", "127.0.0.1:8088"), PublicURL: envDefault("COVEE_PUBLIC_URL", "http://127.0.0.1:8088"), AdminToken: adminToken, HeadscaleURL: os.Getenv("COVEE_HEADSCALE_URL"), HeadscaleAPIKey: apiKey, HeadscaleCAFile: os.Getenv("COVEE_HEADSCALE_CA_FILE"), DataDir: envDefault("COVEE_DATA_DIR", "./data"), AllowHTTP: os.Getenv("COVEE_ALLOW_HTTP") == "true"}
	c.ControlURL = os.Getenv("COVEE_CONTROL_URL")
	if raw := os.Getenv("COVEE_ADDITIONAL_ORIGINS"); raw != "" {
		c.AdditionalOrigins = strings.Split(raw, ",")
	}
	c.AuthMode = envDefault("COVEE_AUTH_MODE", "token")
	c.OIDCIssuer = os.Getenv("COVEE_OIDC_ISSUER")
	c.OIDCClientID = os.Getenv("COVEE_OIDC_CLIENT_ID")
	c.OIDCClientSecret = oidcSecret
	c.OIDCLabel = os.Getenv("COVEE_OIDC_LABEL")
	c.TLSCertFile = os.Getenv("COVEE_TLS_CERT_FILE")
	c.TLSKeyFile = os.Getenv("COVEE_TLS_KEY_FILE")
	c.GatewayTag = os.Getenv("COVEE_GATEWAY_TAG")
	c.GatewayDir = os.Getenv("COVEE_GATEWAY_DIR")
	if c.mode() == "oidc" {
		if _, set := os.LookupEnv("COVEE_ADMIN_TOKEN"); set {
			return Config{}, errors.New("COVEE_ADMIN_TOKEN must be unset in OIDC mode")
		}
		if _, set := os.LookupEnv("COVEE_ADMIN_TOKEN_FILE"); set {
			return Config{}, errors.New("COVEE_ADMIN_TOKEN_FILE must be unset in OIDC mode")
		}
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// secretFromEnv treats presence, including an empty value, as configuration.
// A value and its _FILE alternative must never both be present. File sources
// may be symlinks (as used by projected Kubernetes secrets) to regular files.
func secretFromEnv(name string) (string, error) {
	value, valueSet := os.LookupEnv(name)
	fileName := name + "_FILE"
	path, fileSet := os.LookupEnv(fileName)
	if valueSet && fileSet {
		return "", fmt.Errorf("%s and %s must not both be set", name, fileName)
	}
	if !fileSet {
		return value, nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must name an absolute path", fileName)
	}
	// Reject ordinary special-file paths before opening, and verify the opened
	// descriptor too. Secret mounts are trusted local storage.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must name a readable regular file", fileName)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s must name a readable regular file", fileName)
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must name a readable regular file", fileName)
	}
	const maxSecretFileBytes = 8192
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s could not be read", fileName)
	}
	if len(data) > maxSecretFileBytes {
		return "", fmt.Errorf("%s must contain at most %d bytes", fileName, maxSecretFileBytes)
	}
	value = strings.TrimSuffix(string(data), "\n")
	if len(value) < len(data) {
		value = strings.TrimSuffix(value, "\r")
	}
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", fileName)
	}
	return value, nil
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c Config) validate() error {
	if (c.GatewayTag == "") != (c.GatewayDir == "") {
		return errors.New("COVEE_GATEWAY_TAG and COVEE_GATEWAY_DIR must be set together")
	}
	if c.GatewayTag != "" && (!validTags([]string{c.GatewayTag}) || !filepath.IsAbs(c.GatewayDir)) {
		return errors.New("COVEE_GATEWAY_TAG must be a tag such as tag:covee-gateway and COVEE_GATEWAY_DIR an absolute path")
	}
	switch c.mode() {
	case "token":
		if len(c.AdminToken) < 32 || strings.TrimSpace(c.AdminToken) != c.AdminToken || strings.ContainsAny(c.AdminToken, "\r\n") {
			return errors.New("COVEE_ADMIN_TOKEN must contain at least 32 characters without surrounding whitespace or line breaks")
		}
		if c.OIDCIssuer != "" || c.OIDCClientID != "" || c.OIDCClientSecret != "" || c.OIDCLabel != "" {
			return errors.New("OIDC settings require COVEE_AUTH_MODE=oidc")
		}
	case "oidc":
		if c.AdminToken != "" {
			return errors.New("administrator tokens are disabled in OIDC mode")
		}
		if !validHTTPSURL(c.OIDCIssuer) || strings.HasSuffix(c.OIDCIssuer, "/") {
			return errors.New("COVEE_OIDC_ISSUER must be an exact HTTPS issuer URL without a trailing slash")
		}
		issuer, _ := url.Parse(c.OIDCIssuer)
		if strings.EqualFold(issuer.Hostname(), "login.microsoftonline.com") {
			parts := strings.Split(strings.Trim(issuer.Path, "/"), "/")
			if len(parts) != 2 || parts[1] != "v2.0" || parts[0] == "common" || parts[0] == "organizations" || parts[0] == "consumers" {
				return errors.New("Entra OIDC requires a tenant-specific v2.0 issuer")
			}
		}
		if c.OIDCClientID == "" || len(c.OIDCClientID) > 200 || strings.TrimSpace(c.OIDCClientID) != c.OIDCClientID || strings.ContainsAny(c.OIDCClientID, "\r\n") {
			return errors.New("COVEE_OIDC_CLIENT_ID is required without surrounding whitespace or line breaks")
		}
		if c.OIDCClientSecret == "" || strings.TrimSpace(c.OIDCClientSecret) != c.OIDCClientSecret || strings.ContainsAny(c.OIDCClientSecret, "\r\n") {
			return errors.New("COVEE_OIDC_CLIENT_SECRET is required without surrounding whitespace or line breaks")
		}
		if !validHTTPSURL(c.PublicURL) {
			return errors.New("OIDC requires an HTTPS COVEE_PUBLIC_URL")
		}
		if c.OIDCLabel != "" && (!validText(c.OIDCLabel, 1, 100) || strings.TrimSpace(c.OIDCLabel) != c.OIDCLabel) {
			return errors.New("COVEE_OIDC_LABEL must contain at most 100 display characters without surrounding whitespace")
		}
	default:
		return errors.New("COVEE_AUTH_MODE must be token or oidc")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("COVEE_TLS_CERT_FILE and COVEE_TLS_KEY_FILE must both be configured")
	}
	if c.TLSCertFile != "" && (!filepath.IsAbs(c.TLSCertFile) || !filepath.IsAbs(c.TLSKeyFile)) {
		return errors.New("COVEE_TLS_CERT_FILE and COVEE_TLS_KEY_FILE must name absolute paths")
	}
	if c.HeadscaleAPIKey == "" || strings.TrimSpace(c.HeadscaleAPIKey) != c.HeadscaleAPIKey || strings.ContainsAny(c.HeadscaleAPIKey, "\r\n") {
		return errors.New("COVEE_HEADSCALE_API_KEY is required without surrounding whitespace or line breaks")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return errors.New("COVEE_LISTEN must be a host:port address")
	}
	if c.DataDir == "" {
		return errors.New("COVEE_DATA_DIR is required")
	}
	if c.ControlURL != "" {
		if u, err := url.Parse(c.ControlURL); err != nil || u.Scheme != "https" || u.Host == "" || c.ControlURL != "https://"+u.Host {
			return errors.New("COVEE_CONTROL_URL must be an exact https:// origin")
		}
	}
	if len(c.AdditionalOrigins) > 4 {
		return errors.New("COVEE_ADDITIONAL_ORIGINS lists at most 4 origins")
	}
	seen := map[string]bool{strings.ToLower(c.PublicURL): true}
	for _, origin := range c.AdditionalOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || origin != u.Scheme+"://"+u.Host || seen[strings.ToLower(origin)] {
			return errors.New("COVEE_ADDITIONAL_ORIGINS must be distinct exact https:// origins, separated by commas")
		}
		seen[strings.ToLower(origin)] = true
	}
	for _, entry := range []struct {
		name, raw string
		origin    bool
	}{{"COVEE_PUBLIC_URL", c.PublicURL, true}, {"COVEE_HEADSCALE_URL", c.HeadscaleURL, false}} {
		u, err := url.Parse(entry.raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials, query or fragment", entry.name)
		}
		if entry.origin && (u.Path != "" || u.RawPath != "") {
			return fmt.Errorf("%s must be an exact origin without a trailing slash or path", entry.name)
		}
		if u.Scheme == "http" && !c.AllowHTTP && !loopback(u.Hostname()) {
			return fmt.Errorf("%s requires HTTPS outside loopback; COVEE_ALLOW_HTTP=true is only for isolated testing", entry.name)
		}
		if !entry.origin && u.Path != "" && u.Path != "/" {
			return errors.New("COVEE_HEADSCALE_URL must have no path")
		}
	}
	return nil
}

func (c Config) mode() string {
	if c.AuthMode == "" {
		return "token"
	}
	return c.AuthMode
}

func validHTTPSURL(raw string) bool {
	if len(raw) > 2048 || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.Opaque == "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c Config) client() (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if c.HeadscaleCAFile != "" {
		pem, err := os.ReadFile(c.HeadscaleCAFile)
		if err != nil {
			return nil, fmt.Errorf("read Headscale CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("Headscale CA file contains no valid certificates")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	transport.Proxy = nil // Never send the control-plane credential through an ambient proxy.
	transport.ResponseHeaderTimeout = 10 * time.Second
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

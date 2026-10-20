package management

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var secretEnvNames = []string{"COVEE_ADMIN_TOKEN", "COVEE_HEADSCALE_API_KEY"}

func configTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("COVEE_AUTH_MODE", "token")
	for _, key := range []string{"COVEE_OIDC_ISSUER", "COVEE_OIDC_CLIENT_ID", "COVEE_OIDC_CLIENT_SECRET", "COVEE_OIDC_CLIENT_SECRET_FILE", "COVEE_OIDC_LABEL", "COVEE_TLS_CERT_FILE", "COVEE_TLS_KEY_FILE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range secretEnvNames {
		for _, key := range []string{name, name + "_FILE"} {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("COVEE_ADMIN_TOKEN", "test-admin-token-with-at-least-32-bytes")
	t.Setenv("COVEE_HEADSCALE_API_KEY", "test-headscale-api-key")
	t.Setenv("COVEE_LISTEN", "127.0.0.1:8088")
	t.Setenv("COVEE_PUBLIC_URL", "https://admin.example.test")
	t.Setenv("COVEE_HEADSCALE_URL", "https://headscale.example.test")
	t.Setenv("COVEE_DATA_DIR", t.TempDir())
	t.Setenv("COVEE_ALLOW_HTTP", "false")
}

func TestOIDCDisplayLabelCannotChangeAuthorization(t *testing.T) {
	oidcConfigTestEnv(t)
	t.Setenv("COVEE_OIDC_LABEL", "Continue to sign in")
	c, err := ConfigFromEnv()
	if err != nil || c.OIDCLabel != "Continue to sign in" || c.mode() != "oidc" || c.AdminToken != "" {
		t.Fatal("broker display label changed authentication mode or was lost")
	}
	for _, label := range []string{" padding", "padding ", "first\nsecond", strings.Repeat("x", 101)} {
		t.Setenv("COVEE_OIDC_LABEL", label)
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatal("invalid display label accepted")
		}
	}
	configTestEnv(t)
	t.Setenv("COVEE_OIDC_LABEL", "Continue to sign in")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("token mode accepted OIDC-only display configuration")
	}
}

func oidcConfigTestEnv(t *testing.T) {
	t.Helper()
	configTestEnv(t)
	if err := os.Unsetenv("COVEE_ADMIN_TOKEN"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COVEE_AUTH_MODE", "oidc")
	t.Setenv("COVEE_OIDC_ISSUER", "https://login.microsoftonline.com/tenant-id/v2.0")
	t.Setenv("COVEE_OIDC_CLIENT_ID", "console-client")
	t.Setenv("COVEE_OIDC_CLIENT_SECRET_FILE", secretTestFile(t, "mounted-oidc-secret\r\n"))
}

func TestOIDCConfigurationAndMountedSecret(t *testing.T) {
	oidcConfigTestEnv(t)
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthMode != "oidc" || c.AdminToken != "" || c.OIDCClientSecret != "mounted-oidc-secret" {
		t.Fatal("OIDC configuration did not preserve the selected mode and secret")
	}
}

func TestOIDCConfigurationFailsClosed(t *testing.T) {
	cases := []struct{ key, value string }{
		{"COVEE_AUTH_MODE", "unknown"},
		{"COVEE_ADMIN_TOKEN", ""},
		{"COVEE_ADMIN_TOKEN_FILE", ""},
		{"COVEE_OIDC_ISSUER", "http://issuer.example.test"},
		{"COVEE_OIDC_ISSUER", "https://login.microsoftonline.com/common/v2.0"},
		{"COVEE_OIDC_ISSUER", "https://login.microsoftonline.com/organizations/v2.0"},
		{"COVEE_OIDC_ISSUER", "https://login.microsoftonline.com/consumers/v2.0"},
		{"COVEE_OIDC_ISSUER", "https://issuer.example.test/"},
		{"COVEE_OIDC_ISSUER", "https://issuer.example.test/contains space"},
		{"COVEE_OIDC_ISSUER", "https://issuer.example.test/" + strings.Repeat("x", 2048)},
		{"COVEE_OIDC_CLIENT_ID", ""},
		{"COVEE_OIDC_CLIENT_ID", strings.Repeat("x", 201)},
		{"COVEE_OIDC_CLIENT_SECRET_FILE", ""},
		{"COVEE_OIDC_CLIENT_SECRET", "conflicting-sensitive-oidc-secret"},
		{"COVEE_PUBLIC_URL", "http://127.0.0.1:8088"},
		{"COVEE_PUBLIC_URL", "https://admin.example.test/"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			oidcConfigTestEnv(t)
			t.Setenv("COVEE_ALLOW_HTTP", "true")
			t.Setenv(tc.key, tc.value)
			c, err := ConfigFromEnv()
			if err == nil || !reflect.DeepEqual(c, Config{}) || strings.Contains(err.Error(), "conflicting-sensitive-oidc-secret") {
				t.Fatal("invalid OIDC configuration was accepted or exposed a secret")
			}
		})
	}
}

func TestServerTLSConfiguration(t *testing.T) {
	for _, tc := range []struct {
		cert, key string
		valid     bool
	}{
		{"", "", true},
		{"/run/secrets/server.crt", "/run/secrets/server.key", true},
		{"/run/secrets/server.crt", "", false},
		{"", "/run/secrets/server.key", false},
		{"relative.crt", "/run/secrets/server.key", false},
		{"/run/secrets/server.crt", "relative.key", false},
	} {
		t.Run(tc.cert+"/"+tc.key, func(t *testing.T) {
			configTestEnv(t)
			t.Setenv("COVEE_TLS_CERT_FILE", tc.cert)
			t.Setenv("COVEE_TLS_KEY_FILE", tc.key)
			c, err := ConfigFromEnv()
			if (err == nil) != tc.valid || (!tc.valid && !reflect.DeepEqual(c, Config{})) {
				t.Fatal("TLS certificate/key pair validation failed")
			}
		})
	}
}

func secretTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func useSecretFile(t *testing.T, name, path string) {
	t.Helper()
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name+"_FILE", path)
}

func configSecret(c Config, name string) string {
	if name == "COVEE_ADMIN_TOKEN" {
		return c.AdminToken
	}
	return c.HeadscaleAPIKey
}

func TestConfigEnvironmentSecretsRemainCompatible(t *testing.T) {
	configTestEnv(t)
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range secretEnvNames {
		if configSecret(c, name) != os.Getenv(name) {
			t.Fatal("environment secret was changed")
		}
	}
}

func TestConfigMountedSecretsAndEnvironmentCanBeMixed(t *testing.T) {
	for _, name := range secretEnvNames {
		for _, ending := range []struct{ name, value string }{{"exact", ""}, {"LF", "\n"}, {"CRLF", "\r\n"}} {
			t.Run(name+"/"+ending.name, func(t *testing.T) {
				configTestEnv(t)
				want := "mounted-secret-with-at-least-32-bytes"
				useSecretFile(t, name, secretTestFile(t, want+ending.value))
				c, err := ConfigFromEnv()
				if err != nil {
					t.Fatal(err)
				}
				if configSecret(c, name) != want {
					t.Fatal("mounted secret was not preserved apart from one newline")
				}
			})
		}
	}
	configTestEnv(t)
	for _, name := range secretEnvNames {
		useSecretFile(t, name, secretTestFile(t, "both-mounted-secrets-have-at-least-32-bytes\n"))
	}
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigProjectedSecretSymlinksAreAccepted(t *testing.T) {
	configTestEnv(t)
	for _, name := range secretEnvNames {
		path := secretTestFile(t, "projected-secret-with-at-least-32-bytes")
		link := filepath.Join(t.TempDir(), "projected")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		useSecretFile(t, name, link)
	}
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSecretSourceConflictsFailClosedEvenWhenEmpty(t *testing.T) {
	for _, name := range secretEnvNames {
		for _, value := range []struct{ name, value string }{{"empty", ""}, {"nonempty", "conflicting-secret-value-with-at-least-32-bytes"}} {
			for _, file := range []string{"empty", "valid"} {
				t.Run(name+"/"+value.name+"/"+file, func(t *testing.T) {
					configTestEnv(t)
					t.Setenv(name, value.value)
					path := ""
					if file == "valid" {
						path = secretTestFile(t, "valid-mounted-secret-with-at-least-32-bytes")
					}
					t.Setenv(name+"_FILE", path)
					c, err := ConfigFromEnv()
					if err == nil || !strings.Contains(err.Error(), "must not both be set") {
						t.Fatal("ambiguous secret sources were not rejected")
					}
					if !reflect.DeepEqual(c, Config{}) || (value.value != "" && strings.Contains(err.Error(), value.value)) {
						t.Fatal("rejected configuration exposed a secret")
					}
				})
			}
		}
	}
}

func TestConfigSecretFilesRejectInvalidSourcesWithoutLeakingValues(t *testing.T) {
	const marker = "sensitive-marker-do-not-print"
	for _, name := range secretEnvNames {
		for _, kind := range []string{"absent", "relative", "empty-path", "missing", "directory", "empty", "newline-only", "oversized", "extra-newline", "internal-linebreak", "space-prefix", "space-suffix"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				configTestEnv(t)
				var path string
				switch kind {
				case "absent":
					if err := os.Unsetenv(name); err != nil {
						t.Fatal(err)
					}
				case "relative":
					path = marker
				case "empty-path":
					path = ""
				case "missing":
					path = filepath.Join(t.TempDir(), marker)
				case "directory":
					path = t.TempDir()
				case "empty":
					path = secretTestFile(t, "")
				case "newline-only":
					path = secretTestFile(t, "\r\n")
				case "oversized":
					path = secretTestFile(t, strings.Repeat(marker, 8193/len(marker)+1))
				case "extra-newline":
					path = secretTestFile(t, marker+"-at-least-32-bytes\n\n")
				case "internal-linebreak":
					path = secretTestFile(t, marker+"\n-at-least-32-bytes\n")
				case "space-prefix":
					path = secretTestFile(t, " "+marker+"-at-least-32-bytes\n")
				case "space-suffix":
					path = secretTestFile(t, marker+"-at-least-32-bytes \n")
				}
				if kind != "absent" {
					useSecretFile(t, name, path)
				}
				c, err := ConfigFromEnv()
				if err == nil {
					t.Fatal("invalid secret source was accepted")
				}
				if !reflect.DeepEqual(c, Config{}) || strings.Contains(err.Error(), marker) {
					t.Fatal("rejected configuration exposed a secret or source path")
				}
			})
		}
	}
}

func TestConfigEnvironmentSecretsRejectInternalLineBreaks(t *testing.T) {
	for _, name := range secretEnvNames {
		for _, separator := range []struct{ name, value string }{{"LF", "\n"}, {"CR", "\r"}} {
			t.Run(name+"/"+separator.name, func(t *testing.T) {
				configTestEnv(t)
				secret := "sensitive-environment-secret" + separator.value + "with-line-breaks"
				t.Setenv(name, secret)
				c, err := ConfigFromEnv()
				if err == nil || !reflect.DeepEqual(c, Config{}) {
					t.Fatal("multiline environment secret was accepted or returned in rejected configuration")
				}
				if strings.Contains(err.Error(), "sensitive-environment-secret") {
					t.Fatal("secret validation exposed its value")
				}
			})
		}
	}
}

func TestConfigSecretFileSizeBoundary(t *testing.T) {
	configTestEnv(t)
	for _, name := range secretEnvNames {
		useSecretFile(t, name, secretTestFile(t, strings.Repeat("x", 8192)))
	}
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal("allowed size boundary was rejected:", err)
	}
}

func TestConfigUnreadableSecretFilesFailClosed(t *testing.T) {
	for _, name := range secretEnvNames {
		t.Run(name, func(t *testing.T) {
			configTestEnv(t)
			path := secretTestFile(t, "unreadable-secret-with-at-least-32-bytes")
			if err := os.Chmod(path, 0000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0600) })
			if f, err := os.Open(path); err == nil {
				f.Close()
				t.Skip("test process can read files despite mode 0000")
			}
			useSecretFile(t, name, path)
			if c, err := ConfigFromEnv(); err == nil || !reflect.DeepEqual(c, Config{}) {
				t.Fatal("unreadable secret was accepted or returned in rejected configuration")
			}
		})
	}
}

func TestAdditionalOriginsMustBeDistinctExactHTTPSOrigins(t *testing.T) {
	configTestEnv(t)
	t.Setenv("COVEE_ADDITIONAL_ORIGINS", "https://console.mesh.example.test")
	c, err := ConfigFromEnv()
	if err != nil || len(c.AdditionalOrigins) != 1 || c.AdditionalOrigins[0] != "https://console.mesh.example.test" {
		t.Fatalf("valid additional origin refused: %v %v", c.AdditionalOrigins, err)
	}
	for _, bad := range []string{"http://console.mesh.example.test", "https://console.mesh.example.test/", "https://console.mesh.example.test/path",
		"https://admin.example.test", "https://a.example.test,https://a.example.test", "https://user@console.example.test", "console.mesh.example.test",
		"https://a.test,https://b.test,https://c.test,https://d.test,https://e.test"} {
		t.Setenv("COVEE_ADDITIONAL_ORIGINS", bad)
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatalf("additional origins %q accepted", bad)
		}
	}
}

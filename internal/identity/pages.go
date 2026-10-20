package identity

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

// The broker's pages share one look: the Covee mark on a centred card in the
// system font, light or dark with the device. Everything is inline because
// the pages' Content-Security-Policy allows inline styles and nothing else
// (the Covee account pages also load their own script).

//go:embed assets/covee-mark.svg
var markSVG string

const pageCSS = `:root{--bg:#F2F5FA;--card:#FFFFFF;--ink:#1F2A44;--muted:#5B6478;--line:#D9DFE9;--hover:#F6F8FC;--accent:#2563EB;--accent-hover:#1D4FD8;--field:#FFFFFF;--danger:#B42318;--danger-bg:#FEF3F2;--code:#EEF2F8}
@media (prefers-color-scheme:dark){:root{--bg:#0B1120;--card:#141C2F;--ink:#E7EBF3;--muted:#9AA4B8;--line:#28334D;--hover:#1A2440;--field:#0F172A;--danger:#FDA29B;--danger-bg:#3A1714;--code:#1E2942}}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;color:var(--ink);background:var(--bg);-webkit-font-smoothing:antialiased}
main{width:100%;max-width:400px;background:var(--card);border-radius:20px;padding:36px 28px 28px;box-shadow:0 1px 2px rgba(16,24,40,.06),0 16px 40px rgba(16,24,40,.10)}
.mark{display:flex;justify-content:center;margin:0 0 20px}
.mark svg{width:56px;height:56px;border-radius:13px}
h1{font-size:22px;line-height:1.3;font-weight:650;letter-spacing:-.01em;text-align:center;margin:0 0 6px}
h2{font-size:16px;font-weight:620;margin:0 0 8px}
p{margin:0 0 12px}
.lead{color:var(--muted);text-align:center;margin:0 0 26px}
.stack{display:grid;gap:12px}
button,.button{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;min-height:48px;padding:12px 16px;border:1px solid var(--line);border-radius:12px;background:var(--field);color:var(--ink);font:inherit;font-weight:560;text-decoration:none;cursor:pointer;transition:background .15s,border-color .15s}
button:hover,.button:hover{background:var(--hover);border-color:#B9C3D4}
button:focus-visible,.button:focus-visible,input:focus-visible{outline:3px solid rgba(37,99,235,.35);outline-offset:2px}
button svg{width:20px;height:20px;flex:none}
.primary{background:var(--accent);border-color:var(--accent);color:#FFFFFF}
.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
label{display:block;font-weight:560;font-size:15px;margin:16px 0 6px}
input{display:block;width:100%;min-height:46px;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--field);color:var(--ink);font:inherit}
form button{margin-top:20px}
.divider{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:14px;margin:24px 0 4px}
.divider:before,.divider:after{content:"";flex:1;height:1px;background:var(--line)}
.alert{background:var(--danger-bg);color:var(--danger);border-radius:10px;padding:10px 14px;margin:0 0 18px;font-size:15px}
.note{color:var(--muted);font-size:14px;text-align:center;margin:22px 0 0}
.status{color:var(--muted);font-size:15px;text-align:center;min-height:1.5em;margin:12px 0 0}
dl{margin:0 0 18px;border:1px solid var(--line);border-radius:12px;padding:4px 14px}
dl div{padding:10px 0;border-top:1px solid var(--line)}
dl div:first-child{border-top:0}
dt{color:var(--muted);font-size:13px}
dd{margin:2px 0 0;font-weight:560;word-break:break-all}
code{font:14px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);border-radius:6px;padding:2px 6px;word-break:break-all}
.qr{display:flex;justify-content:center;margin:8px 0 12px}
.qr img{width:200px;height:200px;image-rendering:pixelated;background:#FFFFFF;padding:8px;border-radius:10px}
footer{margin-top:22px;color:var(--muted);font-size:13px;text-align:center}`

// Provider marks, drawn as each provider's sign-in branding shows them.
var providerIcons = map[string]template.HTML{
	"entra":  `<svg viewBox="0 0 21 21" aria-hidden="true"><path fill="#F25022" d="M0 0h10v10H0z"/><path fill="#7FBA00" d="M11 0h10v10H11z"/><path fill="#00A4EF" d="M0 11h10v10H0z"/><path fill="#FFB900" d="M11 11h10v10H11z"/></svg>`,
	"google": `<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`,
	"apple":  `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"/></svg>`,
	"local":  `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>`,
}

// pageData feeds every page; each page uses the fields it needs.
type pageData struct {
	Title     string
	Host      string
	Console   bool
	State     string
	Providers []providerChoice
	Error     string
	Provider  string
	Subject   string
	Target    string
	Message   string
}

type providerChoice struct {
	ID, Name string
	Icon     template.HTML
}

const layout = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>{{.Title}} · Covee</title>{{block "head" .}}{{end}}<style>` + pageCSS + `</style></head><body><main><div class="mark">{{mark}}</div>{{template "content" .}}</main>{{if .Host}}<footer>Covee · {{.Host}}</footer>{{end}}{{block "script" .}}{{end}}</body></html>`

var base = template.Must(template.New("layout").Funcs(template.FuncMap{"mark": func() template.HTML { return template.HTML(markSVG) }}).Parse(layout))

func pageTemplate(content string) *template.Template {
	return template.Must(template.Must(base.Clone()).Parse(content))
}

var chooser = pageTemplate(`{{define "content"}}<h1>Sign in</h1><p class="lead">{{if .Console}}to manage your Covee network{{else}}to add this device to your Covee network{{end}}</p><form method="post" action="/identity/select" class="stack"><input type="hidden" name="state" value="{{.State}}">{{range .Providers}}<button name="provider" value="{{.ID}}">{{.Icon}}<span>Continue with {{.Name}}</span></button>{{end}}</form><p class="note">Your account is used only to confirm who you are.</p>{{end}}`)

var redirectPage = pageTemplate(`{{define "head"}}<meta http-equiv="refresh" content="0;url={{.Target}}">{{end}}{{define "content"}}<h1>Continuing to {{.Provider}}</h1><p class="lead">If nothing happens, use the button below.</p><a class="button primary" href="{{.Target}}">Continue</a>{{end}}`)

var deniedPage = pageTemplate(`{{define "content"}}<h1>Waiting for approval</h1><p class="lead">You signed in, but this account has not been approved for this network yet.</p><dl><div><dt>Signed in with</dt><dd>{{.Provider}}</dd></div><div><dt>Account ID</dt><dd><code>{{.Subject}}</code></dd></div></dl><p>Send this account ID to the person who manages the network. They approve it in the Covee admin console or with <code>covee grant</code>. Then sign in again.</p>{{end}}`)

var errorPage = pageTemplate(`{{define "content"}}<h1>{{.Title}}</h1><p class="lead">{{.Message}}</p>{{end}}`)

var localSignIn = pageTemplate(`{{define "content"}}<h1>Sign in</h1><p class="lead">with your Covee account</p>{{if .Error}}<p class="alert" role="alert">{{.Error}}</p>{{end}}<button id="passkey" class="primary" type="button" data-state="{{.State}}">Sign in with a passkey</button><p id="status" class="status" role="status"></p><div class="divider">or use your password</div><form method="post" action="/identity/local/password"><input type="hidden" name="state" value="{{.State}}"><label for="signin-email">Email</label><input id="signin-email" name="email" type="email" autocomplete="username" required><label for="signin-password">Password</label><input id="signin-password" name="password" type="password" autocomplete="current-password" required><label for="signin-code">Code from your authenticator app</label><input id="signin-code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><button class="primary">Sign in</button></form>{{end}}{{define "script"}}<script src="/identity/local/app.js"></script>{{end}}`)

var invitePage = pageTemplate(`{{define "content"}}<div id="invite"><h1>Set up your Covee account</h1><p id="who" class="lead"></p><p id="status" class="status" role="status">Checking your invitation…</p><section id="choose" class="stack" hidden><button id="create-passkey" class="primary" type="button">Create a passkey (recommended)</button><button id="use-password" type="button">Use a password and an authenticator app</button></section><section id="password" hidden><p>Add this account to an authenticator app, such as 1Password, Google Authenticator or Microsoft Authenticator, by scanning the code or typing the key.</p><div class="qr"><img id="qr" alt="QR code for your authenticator app" hidden></div><p>Key: <code id="secret"></code></p><form id="password-form"><label for="new-password">New password (at least 12 characters)</label><input id="new-password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><label for="code">Code from your authenticator app</label><input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><button class="primary">Save</button></form></section><section id="done" hidden><p class="lead">Your account is ready. Sign in to Covee from the app or the admin console.</p></section></div>{{end}}{{define "script"}}<script src="/identity/local/app.js"></script>{{end}}`)

// friendlyErrors explains, in plain words, why a browser sign-in stopped.
var friendlyErrors = map[string][2]string{
	"invalid_request":         {"This sign-in has expired", "Go back to the Covee app or the admin console and start signing in again."},
	"origin_rejected":         {"This sign-in has expired", "Go back to the Covee app or the admin console and start signing in again."},
	"authentication_failed":   {"Sign-in did not finish", "The sign-in was cancelled or could not be confirmed. Go back to the Covee app and try again."},
	"rate_limited":            {"Too many sign-ins at once", "Wait a few seconds, then try again."},
	"temporarily_unavailable": {"Sign-in is busy", "Wait a moment, then try again."},
	"not_found":               {"Page not found", "Start signing in from the Covee app or the admin console."},
}

// browserWriter marks a response to a top-level browser navigation, so that
// deny answers it with a page rather than JSON.
type browserWriter struct {
	http.ResponseWriter
	host string
}

// asBrowser wraps w for the sign-in pages a person's browser navigates to.
// Requests from programs (no text/html in Accept) keep JSON errors.
func asBrowser(w http.ResponseWriter, r *http.Request, host string) http.ResponseWriter {
	path := r.URL.Path
	navigation := path == "/identity/authorize" || path == "/identity/select" || path == "/identity/local/password" || strings.HasPrefix(path, "/identity/callback/")
	if navigation && strings.Contains(r.Header.Get("Accept"), "text/html") {
		return browserWriter{w, host}
	}
	return w
}

func renderError(b browserWriter, status int, code string) {
	text, ok := friendlyErrors[code]
	if !ok {
		text = [2]string{"Sign-in did not finish", "Go back to the Covee app and try again."}
	}
	b.Header().Set("Content-Type", "text/html; charset=utf-8")
	b.WriteHeader(status)
	errorPage.Execute(b.ResponseWriter, pageData{Title: text[0], Message: text[1], Host: b.host})
}

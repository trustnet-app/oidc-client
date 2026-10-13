package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

func pretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// renderResult is the surface a tester (or an e2e suite) reads. The testids are
// the contract: `sub`, `id-claims`, `userinfo`, `error`, `token-keys`.
func renderResult(w http.ResponseWriter, f *flowState) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, page)
	fmt.Fprintf(w, `<h1>Flow result — %s</h1>`, html.EscapeString(env.Label))
	fmt.Fprintf(w, `<p class=muted>state <code data-testid="flow-state">%s</code></p>`, html.EscapeString(f.State))

	if f.Error != "" {
		fmt.Fprintf(w, `<div class=card><h2>Error</h2><pre data-testid="error">%s</pre></div>`,
			html.EscapeString(f.Error))
	}

	if f.Code != "" {
		fmt.Fprintf(w, `<div class=card><h2>Authorization code</h2><pre data-testid="code">%s</pre></div>`,
			html.EscapeString(f.Code))
	}

	if len(f.IDClaims) > 0 {
		sub, _ := f.IDClaims["sub"].(string)
		fmt.Fprint(w, `<div class=card><h2>ID token — sub (PPID)</h2>`)
		fmt.Fprintf(w, `<p class=ppid data-testid="sub">%s</p>`, html.EscapeString(sub))
		fmt.Fprintf(w, `<h2>ID token claims</h2><pre data-testid="id-claims">%s</pre></div>`,
			html.EscapeString(pretty(f.IDClaims)))
	}

	if len(f.UserInfo) > 0 {
		fmt.Fprintf(w, `<div class=card><h2>/userinfo</h2><pre data-testid="userinfo">%s</pre></div>`,
			html.EscapeString(pretty(f.UserInfo)))
	}

	if len(f.TokenResp) > 0 {
		// Token VALUES are redacted in the HTML: this page is screenshotted on
		// failure and the artefacts outlive the run. /debug/state carries the
		// real values for the assertions that need them.
		keys := map[string]any{}
		for k, v := range f.TokenResp {
			switch k {
			case "access_token", "refresh_token", "id_token":
				s, _ := v.(string)
				keys[k] = fmt.Sprintf("<%d chars>", len(s))
			default:
				keys[k] = v
			}
		}
		fmt.Fprintf(w, `<div class=card><h2>Token response (values redacted)</h2><pre data-testid="token-keys">%s</pre></div>`,
			html.EscapeString(pretty(keys)))
	}

	if accessToken, ok := f.TokenResp["access_token"].(string); ok && accessToken != "" && env.MachineURL != "" {
		// The machine-plane read, deliberately distinct from the OIDC /userinfo
		// above: this is the client's server-to-server call to persona-api's
		// /api/rp/v1/userinfo with the consent-time token. Unlike the token card
		// this reveals the token and the raw request/response — but only after an
		// explicit click, and it shows the client its OWN credential + data.
		fmt.Fprint(w, `<div class=card><h2>TrustNet machine-plane userinfo</h2>`)
		fmt.Fprintf(w, `<form method=post action="/rp-userinfo">`+
			`<input type=hidden name=state value="%s">`+
			`<button type=submit data-testid="test-userinfo">Test userinfo endpoint</button></form>`,
			html.EscapeString(f.State))
		if f.MachineProbe != nil {
			renderMachineProbe(w, f.MachineProbe)
		}
		fmt.Fprint(w, `</div>`)
	}

	fmt.Fprint(w, `<p class=muted><a href="/">← new flow</a> · <a href="/debug/state">/debug/state</a></p>`)
}

// renderAuthRequest shows the exact authorization request the client sends, so
// a developer can inspect it before the browser follows it. The home form's
// "Preview request" button reaches this (/start?preview=1); the flow is already
// stored, so "Continue" navigates to the same URL /start would redirect to.
func renderAuthRequest(w http.ResponseWriter, f *flowState) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, page)
	fmt.Fprintf(w, `<h1>Authorization request — %s</h1>`, html.EscapeString(env.Label))
	fmt.Fprint(w, `<p class=muted>Nothing has been sent yet. This is the exact request the browser will send to the issuer.</p>`)

	fmt.Fprintf(w, `<div class=card><h2>Request URL</h2><pre data-testid="auth-request-url">%s</pre></div>`,
		html.EscapeString(f.AuthURL))

	params := "<could not parse request URL>"
	if u, err := url.Parse(f.AuthURL); err == nil {
		params = formatQuery(u.Query())
	}
	fmt.Fprintf(w, `<div class=card><h2>Query parameters (decoded)</h2><pre data-testid="auth-request-params">%s</pre></div>`,
		html.EscapeString(params))

	fmt.Fprintf(w, `<p><a class=button href="%s">Continue to issuer →</a> · <a href="/">← back</a></p>`,
		html.EscapeString(f.AuthURL))
}

// formatQuery renders authorize query parameters for inspection, one per line
// with the names aligned. The `claims` parameter is JSON, so it is decoded and
// pretty-printed rather than shown as one escaped line.
func formatQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	width := 0
	for _, k := range keys {
		if len(k) > width {
			width = len(k)
		}
	}
	var b strings.Builder
	for _, k := range keys {
		for _, v := range q[k] {
			if k == "claims" {
				fmt.Fprintf(&b, "%-*s = %s\n", width, k, prettyJSON(v))
				continue
			}
			fmt.Fprintf(&b, "%-*s = %s\n", width, k, v)
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// prettyJSON pretty-prints a JSON string, falling back to the raw text when it
// is not decodable (so a malformed claims parameter is still inspectable).
func prettyJSON(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	return pretty(v)
}

// renderMachineProbe shows what the "Test userinfo endpoint" button did: the
// token it used, the request it made, and the response it got back.
func renderMachineProbe(w http.ResponseWriter, p *machineProbe) {
	fmt.Fprintf(w, `<h2>Token</h2><pre data-testid="mp-token">%s</pre>`,
		html.EscapeString(p.Token))

	req := p.Method + " " + p.URL + "\n"
	for _, k := range []string{"Authorization"} {
		if v, ok := p.Headers[k]; ok {
			req += k + ": " + v + "\n"
		}
	}
	fmt.Fprintf(w, `<h2>Request</h2><pre data-testid="mp-request">%s</pre>`,
		html.EscapeString(strings.TrimSuffix(req, "\n")))

	resp := ""
	if p.Error != "" {
		resp = p.Error
	} else {
		resp = fmt.Sprintf("HTTP %d\n%s", p.Status, p.Response)
	}
	fmt.Fprintf(w, `<h2>Response</h2><pre data-testid="mp-response">%s</pre>`,
		html.EscapeString(strings.TrimSuffix(resp, "\n")))
}

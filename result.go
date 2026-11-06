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
func renderResult(w http.ResponseWriter, f *flowState, signedIn bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · result", "result", signedIn)

	fmt.Fprintf(w, `<section class="page-head">
<p class="eyebrow">Authorization Code Flow · Result</p>
<h1>Flow result — %s</h1>
<p class="muted">state <code data-testid="flow-state">%s</code></p>
</section>`, html.EscapeString(env.Label), html.EscapeString(f.State))

	if f.Error != "" {
		fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>Error</h2><span class="badge danger">failed</span></div><pre data-testid="error">%s</pre></section>`,
			html.EscapeString(f.Error))
	}

	if f.Code != "" {
		fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>Authorization code</h2><span class="badge">received</span></div><pre data-testid="code">%s</pre></section>`,
			html.EscapeString(f.Code))
	}

	if f.Escalation && f.Error == "" && len(f.RequestedClaims) > 0 {
		renderEscalationOutcome(w, f)
	}

	if len(f.IDClaims) > 0 {
		sub, _ := f.IDClaims["sub"].(string)
		fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>ID token</h2><span class="badge ok">decoded</span></div>`)
		fmt.Fprintf(w, `<dl class="kv"><dt>sub (PPID)</dt><dd class="mono" data-testid="sub">%s</dd></dl>`, html.EscapeString(sub))
		fmt.Fprintf(w, `<h2>Claims</h2><pre data-testid="id-claims">%s</pre></section>`,
			html.EscapeString(pretty(f.IDClaims)))
	}

	if len(f.UserInfo) > 0 {
		fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>OIDC /userinfo</h2><span class="badge accent">userinfo</span></div><pre data-testid="userinfo">%s</pre></section>`,
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
		fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>Token response (values redacted)</h2><span class="badge">redacted</span></div><pre data-testid="token-keys">%s</pre></section>`,
			html.EscapeString(pretty(keys)))
	}

	if accessToken, ok := f.TokenResp["access_token"].(string); ok && accessToken != "" && env.MachineURL != "" {
		// The machine-plane read, deliberately distinct from the OIDC /userinfo
		// above: this is the client's server-to-server call to persona-api's
		// /api/rp/v1/userinfo with the consent-time token. Unlike the token card
		// this reveals the token and the raw request/response — but only after an
		// explicit click, and it shows the client its OWN credential + data.
		fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>TrustNet machine-plane userinfo</h2><span class="badge accent">probe</span></div>`)
		fmt.Fprint(w, `<p class="muted">The RP's own consent-time access token, sent to <code>/api/rp/v1/userinfo</code>.</p>`)
		fmt.Fprintf(w, `<form method="post" action="/rp-userinfo"><input type="hidden" name="state" value="%s"><button class="btn secondary" type="submit" data-testid="test-userinfo">Test userinfo endpoint</button></form>`,
			html.EscapeString(f.State))
		if f.MachineProbe != nil {
			renderMachineProbe(w, f.MachineProbe)
		}
		fmt.Fprint(w, `</section>`)
	}

	fmt.Fprint(w, `<div class="row actions"><a class="btn" href="/">New flow</a><a class="btn secondary" href="/debug/state">/debug/state</a></div>`)
	pageEnd(w)
}

// renderEscalationOutcome compares the requested claim names with the claims
// TrustNet actually returned. It shows names and statuses only, never values.
func renderEscalationOutcome(w http.ResponseWriter, f *flowState) {
	prior := map[string]bool{}
	for _, name := range f.PriorClaims {
		prior[name] = true
	}
	returned := 0
	for _, name := range f.RequestedClaims {
		if claimPresent(f.IDClaims, name) || claimPresent(f.UserInfo, name) {
			returned++
		}
	}

	fmt.Fprintf(w, `<section class="card" style="margin-top:1rem" data-testid="escalation-outcome"><div class="card-head"><h2>Escalation outcome</h2><span class="badge accent">%d of %d returned</span></div>`, returned, len(f.RequestedClaims))
	fmt.Fprintf(w, `<p class="muted"><span data-testid="escalation-summary">%d of %d requested claims returned</span>. A claim missing from both the ID token and <code>/userinfo</code> is shown as “Not returned”; the user may have declined it, or the selected persona may have no value for it.</p>`, returned, len(f.RequestedClaims))
	fmt.Fprint(w, `<table><thead><tr><th>Claim</th><th>Source</th><th>Outcome</th></tr></thead><tbody>`)
	for _, name := range f.RequestedClaims {
		source := `<span class="badge">Already shared</span>`
		if !prior[name] {
			source = `<span class="badge accent">New request</span>`
		}
		outcome := `<span class="badge ok">Shared</span>`
		state := "shared"
		if !claimPresent(f.IDClaims, name) && !claimPresent(f.UserInfo, name) {
			outcome = `<span class="badge warn">Not returned</span>`
			state = "not_returned"
		}
		fmt.Fprintf(w, `<tr data-claim="%s" data-outcome="%s"><td class="mono">%s</td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(name), state, html.EscapeString(name), source, outcome)
	}
	fmt.Fprint(w, `</tbody></table></section>`)
}

func claimPresent(m map[string]any, name string) bool {
	if m == nil {
		return false
	}
	v, ok := m[name]
	return ok && v != nil
}

// renderAuthRequest shows the exact authorization request the client sends, so
// a developer can inspect it before the browser follows it. The home form's
// "Preview request" button reaches this (/start?preview=1); the flow is already
// stored, so "Continue" navigates to the same URL /start would redirect to.
func renderAuthRequest(w http.ResponseWriter, f *flowState, signedIn bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · authorization preview", "preview", signedIn)

	fmt.Fprintf(w, `<section class="page-head">
<p class="eyebrow">Authorization Code Flow · Preview</p>
<h1>Authorization request — %s</h1>
<p class="muted">Nothing has been sent yet. This is the exact request the browser will send to the issuer.</p>
</section>`, html.EscapeString(env.Label))

	fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>Request URL</h2><button class="btn ghost small" type="button" data-copy="request-url">Copy</button></div>`)
	fmt.Fprintf(w, `<pre id="request-url" data-testid="auth-request-url">%s</pre></section>`,
		html.EscapeString(f.AuthURL))

	params := "<could not parse request URL>"
	if u, err := url.Parse(f.AuthURL); err == nil {
		params = formatQuery(u.Query())
	}
	fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>Query parameters (decoded)</h2><span class="badge">decoded</span></div><pre data-testid="auth-request-params">%s</pre></section>`,
		html.EscapeString(params))

	fmt.Fprintf(w, `<div class="row actions"><a class="btn" href="%s">Continue to issuer</a><a class="btn secondary" href="/">Back</a></div>`,
		html.EscapeString(f.AuthURL))
	pageEnd(w)
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

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// requestableClaims mirrors the backend's claims.RequestableNames(): the
// storeable scalar catalog plus the derived booleans. Every claim is offered in
// one panel so a tester can register or deregister any of them directly instead
// of typing the `claims` JSON by hand. Sorted for stable rendering.
var requestableClaims = []string{
	"birthdate", "email", "email_verified", "family_name", "gender",
	"given_name", "locale", "middle_name", "name", "nickname", "over_18",
	"phone_number", "phone_number_verified", "picture", "preferred_username",
	"profile", "website", "zoneinfo",
}

// defaultClaims is the subset pre-checked on the form.
var defaultClaims = map[string]bool{
	"email": true, "email_verified": true, "given_name": true, "family_name": true,
}

// promptValues are the OIDC `prompt` values the form offers as ticks. Only
// `consent` is honoured by persona-api (force a full review even on an
// unchanged remembered grant). The ticked set is sent space-delimited; blank
// omits the parameter.
var promptValues = []string{"consent"}

// GET / — the launch form.
func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess, err := currentSession(r)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
		return
	}
	if sess != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pageStart(w, "OIDC · test client", "home")

	fmt.Fprintf(w, `<section class="page-head">
<p class="eyebrow">Authorization Code Flow · Demo Client</p>
<h1 data-testid="rp-label">%s</h1>
<p class="lede">This inspector signs you in with OpenID Connect. Choose the claims
to request, then start the authorization-code flow. The browser is sent to the
issuer and returns with an ID token, an access token, and only the claims you
approved.</p>
<div class="meta-pills">
  <span class="meta-pill"><span class="meta-label">client_id</span><code data-testid="rp-client-id">%s</code></span>
  <span class="meta-sep" aria-hidden="true">·</span>
  <span class="meta-pill"><span class="meta-label">redirect</span><code>%s</code></span>
  <span class="meta-sep" aria-hidden="true">·</span>
  <span class="meta-pill"><span class="meta-label">issuer</span><code>%s</code></span>
</div>
<div class="notice" role="note"><span class="notice-icon" aria-hidden="true">i</span><span>You are signed out. Starting login sends the browser to the issuer.</span></div>
</section>`, html.EscapeString(env.Label), html.EscapeString(env.ClientID),
		html.EscapeString(env.Redirect), html.EscapeString(disc.Issuer))

	fmt.Fprint(w, `<form method="get" action="/start" class="grid">`)

	fmt.Fprint(w, `<fieldset class="panel" data-testid="scope">
<legend class="sr-only">Scope</legend>
<div class="panel-head" aria-hidden="true"><span class="panel-title">Scope</span><span class="panel-badge">OAuth 2.0 / OIDC</span></div>
<div class="checks"><label class="check tile"><input type="checkbox" name="scope" value="openid" checked> <span>openid</span> <span class="req">required</span></label></div>
<p class="hint">The <code>openid</code> scope is required to request an ID token.</p>
</fieldset>`)

	fmt.Fprint(w, `<fieldset class="panel" data-testid="claims">
<legend class="sr-only">Claims</legend>
<div class="panel-head" aria-hidden="true"><span class="panel-title">Claims</span><span class="panel-meta">Standard OpenID Spec</span></div>
<p class="hint">Select any claims to request. Every claim below can be registered or deregistered for this demo client.</p>
<div class="checks claim-grid">`)
	for _, name := range requestableClaims {
		checked := ""
		if defaultClaims[name] {
			checked = " checked"
		}
		fmt.Fprintf(w, `<label class="check tile"><input type="checkbox" name="claim" value="%s"%s> <span>%s</span></label>`,
			html.EscapeString(name), checked, html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)

	fmt.Fprint(w, `<fieldset class="panel" data-testid="prompt">
<legend class="sr-only">prompt (OIDC)</legend>
<div class="panel-head" aria-hidden="true"><span class="panel-title">prompt (OIDC)</span><span class="panel-meta">Interaction Control</span></div>
<div class="checks">`)
	for _, name := range promptValues {
		fmt.Fprintf(w, `<label class="check tile"><input type="checkbox" name="prompt" value="%s"> <span>%s</span></label>`,
			html.EscapeString(name), html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)

	fmt.Fprint(w, `<div class="card code-card">
<div class="code-card-head"><label for="claims">OIDC <code>claims</code> request parameter (JSON, optional — overrides the checkboxes)</label><span class="panel-meta">JSON Editor</span></div>
<div class="code-window">
  <div class="code-window-bar"><span class="code-dots" aria-hidden="true"><i class="dot-red"></i><i class="dot-amber"></i><i class="dot-green"></i><span class="code-file">claims_payload.json</span></span><span class="code-enc">UTF-8</span></div>
  <div class="code-body">
    <div class="code-gutter" aria-hidden="true"><span>1</span><span>2</span><span>3</span><span>4</span></div>
    <textarea id="claims" name="claims" rows="4" placeholder='{"id_token":{"email":{"essential":true}}}'></textarea>
  </div>
</div>
</div>`)

	fmt.Fprint(w, `<div class="row actions">
<button class="btn btn-lg" type="submit" data-testid="start">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
  Start login
</button>
<button class="btn secondary btn-lg" type="submit" name="preview" value="1" data-testid="preview">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
  Preview request
</button>
</div>`)

	fmt.Fprint(w, `</form>`)
	fmt.Fprint(w, `<p class="footer-note">Raw flow state lives at <a href="/debug/state">/debug/state</a>. RP-initiated logout is at <a href="/logout">/logout</a>.</p>`)
	pageEnd(w)
}

// GET /start — build the authorize URL and send the browser to the issuer.
func handleStart(w http.ResponseWriter, r *http.Request) {
	// Scopes arrive as one checkbox value each (name=scope); join them into the
	// space-delimited form the authorize request expects.
	scope := strings.Join(r.URL.Query()["scope"], " ")
	if strings.TrimSpace(scope) == "" {
		scope = "openid"
	}
	claimsParam := strings.TrimSpace(r.URL.Query().Get("claims"))
	if claimsParam == "" {
		// No raw JSON typed: build the `claims` request from the ticked
		// checkboxes (a voluntary `id_token` request — "email": null).
		if ticked := r.URL.Query()["claim"]; len(ticked) > 0 {
			m := map[string]any{}
			for _, name := range ticked {
				m[name] = nil
			}
			b, _ := json.Marshal(map[string]any{"id_token": m})
			claimsParam = string(b)
		}
	}
	f := &flowState{
		State:       randB64(16),
		Nonce:       randB64(16),
		Verifier:    randB64(32),
		ClaimsParam: claimsParam,
		CreatedAt:   time.Now().UTC(),
	}
	q := url.Values{
		"client_id":             {env.ClientID},
		"response_type":         {"code"},
		"scope":                 {scope},
		"redirect_uri":          {env.Redirect},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {pkceChallenge(f.Verifier)},
		"code_challenge_method": {"S256"},
	}
	// `prompt` arrives as one checkbox value each; join the ticked set into the
	// space-delimited form OIDC expects (blank omits the parameter).
	if prompts := r.URL.Query()["prompt"]; len(prompts) > 0 {
		q.Set("prompt", strings.Join(prompts, " "))
	}
	if f.ClaimsParam != "" {
		q.Set("claims", f.ClaimsParam)
	}
	sep := "?"
	if strings.Contains(disc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	f.AuthURL = disc.AuthorizationEndpoint + sep + q.Encode()
	putFlow(f)
	// "Preview request" reaches /start?preview=1: render the exact request
	// instead of following it. The flow is already stored, so the page's
	// "Continue" link goes to the same URL the redirect would.
	if r.URL.Query().Get("preview") != "" {
		renderAuthRequest(w, f)
		return
	}
	http.Redirect(w, r, f.AuthURL, http.StatusFound)
}

// GET /callback (and the REDIRECT_URI path) — the authorization response from
// TrustNet: exchange the code, decode the ID token, fetch userinfo, then
// redirect (PRG) to the result page so the code is not left in the URL.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	f := getFlow(r.URL.Query().Get("state"))
	if f == nil {
		renderError(w, http.StatusBadRequest, "The authorization response carried an unknown state.")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		// The denial path lands here: error, no code, no token exchange. There
		// is no session to protect, so the result page renders the error.
		f.Error = e + ": " + r.URL.Query().Get("error_description")
		putFlow(f)
		redirectToResult(w, r, f.State)
		return
	}
	f.Code = r.URL.Query().Get("code")

	tok, err := exchangeCode(f.Code, f.Verifier)
	if err != nil {
		f.Error = "token exchange: " + err.Error()
		putFlow(f)
		redirectToResult(w, r, f.State)
		return
	}
	f.TokenResp = tok
	if idt, ok := tok["id_token"].(string); ok {
		f.IDClaims = decodeJWT(idt)
	}
	if at, ok := tok["access_token"].(string); ok && disc.UserInfoEndpoint != "" {
		f.UserInfo = fetchUserInfo(at)
	}
	putFlow(f)

	sess, err := startSession(w, r, f)
	if err != nil {
		f.Error = "session: " + err.Error()
		putFlow(f)
		redirectToResult(w, r, f.State)
		return
	}
	log.Printf("session started, expires %s", sess.ExpiresAt.Format(time.RFC3339))
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// redirectToResult applies Post/Redirect/Get: the browser lands on a clean
// /result URL, and the result page's "New flow" button resets to the form.
func redirectToResult(w http.ResponseWriter, r *http.Request, state string) {
	http.Redirect(w, r, "/result?state="+url.QueryEscape(state), http.StatusSeeOther)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	sess, err := currentSession(r)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
		return
	}

	state := r.URL.Query().Get("state")
	var f *flowState
	if state != "" {
		f = getFlow(state)
	} else if sess != nil {
		f = latestFlowForSub(sess.Sub)
	}
	if f == nil {
		renderError(w, http.StatusNotFound, "The requested flow was not found.")
		return
	}

	// A successful flow belongs to a signed-in session. An error flow (denial
	// or token-exchange failure) has no session yet, so it remains inspectable.
	if sess == nil && f.Error == "" {
		renderError(w, http.StatusUnauthorized, "A valid session is required to view this flow.")
		return
	}
	if sess != nil {
		if sub := claimString(f.IDClaims, "sub"); sub != "" && sub != sess.Sub {
			renderError(w, http.StatusUnauthorized, "This flow does not belong to the current session.")
			return
		}
	}
	renderResult(w, f)
}

// POST /backchannel-logout — the issuer calls this on revoke/logout. Records the
// decoded logout token.
func handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	claims := decodeJWT(r.FormValue("logout_token"))
	lastLogoutMu.Lock()
	lastLogout = claims
	lastLogoutMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// GET /debug/state — machine-readable dump for assertions the HTML redacts.
func handleDebugState(w http.ResponseWriter, r *http.Request) {
	fl := allFlows()
	sort.Slice(fl, func(i, j int) bool { return fl[i].CreatedAt.Before(fl[j].CreatedAt) })
	lastLogoutMu.Lock()
	ll := lastLogout
	lastLogoutMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"label":             env.Label,
		"client_id":         env.ClientID,
		"redirect_uri":      env.Redirect,
		"issuer":            disc.Issuer,
		"flows":             fl,
		"last_logout_token": ll,
	})
}

// POST /debug/reset — drop accumulated flow state.
func handleDebugReset(w http.ResponseWriter, r *http.Request) {
	resetFlows()
	if dataStore != nil {
		if err := dataStore.reset(); err != nil {
			log.Printf("debug reset: store: %v", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /purge — TrustNet delivers a signed revocation here. The client verifies
// the compact JWS against TrustNet's JWKS (when JWKS_URL is configured) and
// records the decoded payload. It always answers 200: an invalid body is still
// recorded (`verified:false`, with the error).
func handlePurge(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	rec := purgeDelivery{ReceivedAt: time.Now(), BodyLen: len(body)}
	if env.JWKSURL == "" {
		rec.Error = "JWKS_URL not configured"
	} else if payload, kid, err := verifyWebhookJWS(string(body)); err != nil {
		rec.Error = err.Error()
	} else {
		rec.Verified = true
		rec.Kid = kid
		rec.Payload = payload
	}
	recordPurge(rec)
	w.WriteHeader(http.StatusOK)
}

// GET /debug/purge — machine-readable purge deliveries.
func handleDebugPurge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"purge_deliveries": allPurges()})
}

// verifyWebhookJWS verifies a compact EdDSA JWS against TrustNet's JWKS and
// returns the decoded payload and the signing kid.
func verifyWebhookJWS(compact string) (map[string]any, string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("malformed JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("header: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, "", fmt.Errorf("header json: %w", err)
	}
	if h.Alg != "EdDSA" {
		return nil, "", fmt.Errorf("alg %q, want EdDSA", h.Alg)
	}
	pub, err := jwksKey(h.Kid)
	if err != nil {
		return nil, "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, "", fmt.Errorf("signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, "", fmt.Errorf("signature does not verify")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, "", fmt.Errorf("payload json: %w", err)
	}
	return payload, h.Kid, nil
}

// jwksKey fetches TrustNet's JWKS and returns the Ed25519 public key for kid.
func jwksKey(kid string) (ed25519.PublicKey, error) {
	resp, err := httpc.Get(env.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	for _, k := range set.Keys {
		if k.Kid != kid {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q is not a 32-byte Ed25519 key", kid)
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}

// --- token helpers -----------------------------------------------------------

func exchangeCode(code, verifier string) (map[string]any, error) {
	// Authenticate with whatever the client is registered for: client_secret_post
	// (the seeded default) or client_secret_basic. Mismatching it fails with
	// invalid_client.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {env.Redirect},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequest(http.MethodPost, disc.TokenEndpoint, nil)
	if err != nil {
		return nil, err
	}
	if env.TokenAuthMethod == "basic" {
		// RFC 6749 §2.3.1: form-urlencode the id/secret before Basic auth.
		req.SetBasicAuth(url.QueryEscape(env.ClientID), url.QueryEscape(env.ClientSecret))
	} else {
		form.Set("client_id", env.ClientID)
		form.Set("client_secret", env.ClientSecret)
	}
	body := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%v", m)
	}
	return m, nil
}

func fetchUserInfo(accessToken string) map[string]any {
	req, _ := http.NewRequest(http.MethodGet, disc.UserInfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpc.Do(req)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(body, &m)
	return m
}

// --- machine-plane userinfo probe --------------------------------------------

// machineProbe captures everything the "Test userinfo endpoint" action shows:
// the token it used, the request it made, and the response it got back. This is
// the client's own consent-time access token and the data TrustNet disclosed to
// it — the same data /debug/state already exposes. Not product code.
type machineProbe struct {
	Token    string            `json:"token"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers"`
	Status   int               `json:"status"`
	Response string            `json:"response"`
	Error    string            `json:"error,omitempty"`
}

// probeMachineUserinfo makes the machine-plane userinfo call (GET
// /api/rp/v1/userinfo, Bearer the consent-time token) and records token +
// request + response for display. A non-2xx is a valid result to show — a
// revoked token answering 401 is exactly what an RP wants to see.
func probeMachineUserinfo(token string) *machineProbe {
	endpoint := env.MachineURL + "/api/rp/v1/userinfo"
	p := &machineProbe{
		Token:  token,
		Method: http.MethodGet,
		URL:    endpoint,
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpc.Do(req)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	p.Status = resp.StatusCode
	p.Response = prettyText(body)
	return p
}

// handleRpUserinfo runs the probe for a flow and returns to its result page.
func handleRpUserinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, "This action accepts POST only.")
		return
	}
	sess, err := currentSession(r)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
		return
	}
	if sess == nil {
		renderError(w, http.StatusUnauthorized, "A valid session is required to call the machine-plane userinfo endpoint.")
		return
	}
	if env.MachineURL == "" {
		renderError(w, http.StatusNotImplemented, "MACHINE_URL is not configured.")
		return
	}
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "The probe form could not be read.")
		return
	}
	if sess.AccessToken == "" {
		renderError(w, http.StatusBadRequest, "No access token is stored for this session.")
		return
	}

	p := probeMachineUserinfo(sess.AccessToken)
	if state := r.Form.Get("state"); state != "" {
		f := getFlow(state)
		if f == nil {
			renderError(w, http.StatusNotFound, "The requested flow was not found.")
			return
		}
		if sub := claimString(f.IDClaims, "sub"); sub != "" && sub != sess.Sub {
			renderError(w, http.StatusUnauthorized, "This flow does not belong to the current session.")
			return
		}
		f.MachineProbe = p
		putFlow(f)
		renderResult(w, f)
		return
	}
	renderAccount(w, sess, p)
}

// prettyText pretty-prints a JSON body and leaves anything else verbatim.
func prettyText(raw []byte) string {
	var v any
	if json.Unmarshal(raw, &v) == nil {
		return pretty(v)
	}
	return string(raw)
}

// decodeJWT returns the payload without verifying the signature — an
// inspector, not a validator.
func decodeJWT(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

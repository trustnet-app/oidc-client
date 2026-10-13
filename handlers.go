package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const page = `<!doctype html><meta charset=utf-8>
<title>OIDC · test client</title>
<style>
body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem} h2{font-size:1rem;margin-top:1.5rem}
.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:.75rem 0}
button,a.button{font:inherit;padding:.5rem 1rem;border-radius:6px;border:1px solid #185FA5;background:#185FA5;color:#fff;cursor:pointer;text-decoration:none;display:inline-block}
button.secondary{background:#fff;color:#185FA5}
pre{background:#f7f7f7;padding:.75rem;border-radius:6px;overflow:auto;font-size:.8rem}
textarea,input{width:100%;font-size:.9rem}
label{display:block;margin:.5rem 0 .2rem}
.muted{color:#666;font-size:.85rem}
.ppid{color:#185FA5;font-weight:600}
.claims{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.15rem 1rem}
.claim{display:flex;align-items:center;gap:.4rem;font-size:.85rem;margin:0}
.claim input{width:auto}
fieldset{border:1px solid #ddd;border-radius:6px;margin:.5rem 0;padding:.5rem .75rem}
legend{font-size:.85rem;font-weight:600;padding:0 .35rem}
</style>`

// requestableClaims mirrors the backend's claims.RequestableNames(): the
// storeable scalar catalog plus the derived booleans. The form offers a
// checkbox for each so a tester can request claims directly instead of typing
// the `claims` JSON by hand. Sorted for stable rendering.
var requestableClaims = []string{
	"birthdate", "email", "email_verified", "family_name", "gender",
	"given_name", "locale", "middle_name", "name", "nickname", "over_18",
	"phone_number", "phone_number_verified", "picture", "preferred_username",
	"profile", "website", "zoneinfo",
}

// registeredClaims is the demo clients' registered claim ceiling: the claims
// the RPs declared at registration. The form groups them apart from the rest of
// the requestable catalog, so a tester can see — and request — an *unregistered*
// claim to exercise the consent ceiling.
var registeredClaims = map[string]bool{
	"email": true, "email_verified": true, "given_name": true, "family_name": true,
	"phone_number": true, "phone_number_verified": true,
}

// defaultClaims is the subset of registeredClaims pre-checked on the form.
var defaultClaims = map[string]bool{
	"email": true, "email_verified": true, "given_name": true, "family_name": true,
}

// registeredScopes mirrors the client `scope` registered in the seed. defaultScopes
// is the subset pre-checked: it keeps the long-standing request
// `openid email profile` while leaving `offline_access` available to tick.
var (
	registeredScopes   = []string{"openid", "offline_access", "email", "profile", "phone"}
	defaultScopes      = map[string]bool{"openid": true, "email": true, "profile": true}
	unregisteredScopes = []string{"address"}
)

// promptValues are the OIDC `prompt` values the form offers as ticks. Only
// `consent` is honoured by persona-api (force a full review even on an
// unchanged remembered grant). The ticked set is sent space-delimited; blank
// omits the parameter.
var promptValues = []string{"consent"}

// GET / — the launch form.
func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page)
	fmt.Fprintf(w, `<h1 data-testid="rp-label">%s</h1>`, html.EscapeString(env.Label))
	fmt.Fprintf(w, `<p class=muted>client_id <code data-testid="rp-client-id">%s</code> · redirect <code>%s</code> · issuer <code>%s</code></p>`,
		html.EscapeString(env.ClientID), html.EscapeString(env.Redirect), html.EscapeString(disc.Issuer))
	fmt.Fprint(w, `<form method=get action="/start" class=card>`)
	fmt.Fprint(w, `<fieldset data-testid="scopes-registered"><legend>Registered scopes</legend><div class=claims>`)
	for _, name := range registeredScopes {
		checked := ""
		if defaultScopes[name] {
			checked = " checked"
		}
		fmt.Fprintf(w, `<label class=claim><input type=checkbox name=scope value="%s"%s> %s</label>`,
			html.EscapeString(name), checked, html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)
	fmt.Fprint(w, `<fieldset data-testid="scopes-unregistered"><legend>Unregistered scopes (not in the client registration)</legend><div class=claims>`)
	for _, name := range unregisteredScopes {
		fmt.Fprintf(w, `<label class=claim><input type=checkbox name=scope value="%s"> %s</label>`,
			html.EscapeString(name), html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)
	fmt.Fprint(w, `<fieldset data-testid="claims-registered"><legend>Registered claims (the RP's declared ceiling — tick to request each as an <code>id_token</code> claim)</legend><div class=claims>`)
	for _, name := range requestableClaims {
		if !registeredClaims[name] {
			continue
		}
		checked := ""
		if defaultClaims[name] {
			checked = " checked"
		}
		fmt.Fprintf(w, `<label class=claim><input type=checkbox name=claim value="%s"%s> %s</label>`,
			html.EscapeString(name), checked, html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)
	fmt.Fprint(w, `<fieldset data-testid="claims-unregistered"><legend>Unregistered claims (not declared by the RP — requesting one exercises the ceiling)</legend><div class=claims>`)
	for _, name := range requestableClaims {
		if registeredClaims[name] {
			continue
		}
		fmt.Fprintf(w, `<label class=claim><input type=checkbox name=claim value="%s"> %s</label>`,
			html.EscapeString(name), html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)
	fmt.Fprint(w, `<fieldset data-testid="prompt"><legend>prompt (OIDC — tick to send <code>consent</code>: force a full review even on an unchanged grant; blank omits it)</legend><div class=claims>`)
	for _, name := range promptValues {
		fmt.Fprintf(w, `<label class=claim><input type=checkbox name=prompt value="%s"> %s</label>`,
			html.EscapeString(name), html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)
	fmt.Fprint(w, `<label>OIDC <code>claims</code> request parameter (JSON, optional — overrides the checkboxes)</label>`)
	fmt.Fprint(w, `<textarea name=claims rows=4 placeholder='{"id_token":{"email":{"essential":true}}}'></textarea>`)
	fmt.Fprint(w, `<p><button type=submit data-testid="start">Start login</button> <button type=submit name=preview value=1 class=secondary data-testid="preview">Preview request</button></p>`)
	fmt.Fprint(w, `</form>`)
	fmt.Fprint(w, `<p class=muted><a href="/debug/state">/debug/state</a> · <a href="/logout">RP-initiated logout</a></p>`)
}

// GET /start — build the authorize URL and send the browser to the issuer.
func handleStart(w http.ResponseWriter, r *http.Request) {
	// Scopes arrive as one checkbox value each (name=scope); join them into the
	// space-delimited form the authorize request expects.
	scope := strings.Join(r.URL.Query()["scope"], " ")
	if strings.TrimSpace(scope) == "" {
		scope = "openid email profile"
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
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		// The denial path lands here: error, no code, no token exchange.
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
	redirectToResult(w, r, f.State)
}

// redirectToResult applies Post/Redirect/Get: the browser lands on a clean
// /result URL, and the result page's "New flow" button resets to the form.
func redirectToResult(w http.ResponseWriter, r *http.Request, state string) {
	http.Redirect(w, r, "/result?state="+url.QueryEscape(state), http.StatusSeeOther)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	f := getFlow(r.URL.Query().Get("state"))
	if f == nil {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
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

// GET /logout — RP-initiated logout via the discovered end_session endpoint.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if disc.EndSessionEndpoint == "" {
		http.Error(w, "end_session_endpoint not present in the discovery document", http.StatusNotImplemented)
		return
	}
	var idt string
	newest := time.Time{}
	for _, f := range allFlows() {
		if f.TokenResp == nil || !f.CreatedAt.After(newest) {
			continue
		}
		if s, ok := f.TokenResp["id_token"].(string); ok {
			idt, newest = s, f.CreatedAt
		}
	}
	loc := disc.EndSessionEndpoint + "?post_logout_redirect_uri=" +
		url.QueryEscape(strings.TrimSuffix(env.Redirect, "/callback")+"/")
	if idt != "" {
		loc += "&id_token_hint=" + url.QueryEscape(idt)
	}
	http.Redirect(w, r, loc, http.StatusFound)
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
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if env.MachineURL == "" {
		http.Error(w, "MACHINE_URL not configured", http.StatusNotImplemented)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	f := getFlow(r.Form.Get("state"))
	if f == nil {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	token, _ := f.TokenResp["access_token"].(string)
	if token == "" {
		http.Error(w, "no access token for this flow", http.StatusBadRequest)
		return
	}
	f.MachineProbe = probeMachineUserinfo(token)
	http.Redirect(w, r, "/result?state="+url.QueryEscape(f.State), http.StatusSeeOther)
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

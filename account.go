package main

import (
	"fmt"
	"html"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GET /account — the signed-in home. A missing session redirects to the launch
// form; an expired or tombstoned cookie is handled where the session store is
// consulted.
func handleAccount(w http.ResponseWriter, r *http.Request) {
	sess, err := currentSession(r)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
		return
	}
	if sess == nil {
		ev, err := tombstoneForRequest(r)
		if err != nil {
			renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
			return
		}
		if ev != nil {
			// The notice is shown once: consume the stale cookie, then the next
			// visit renders the launch form.
			clearSessionCookie(w)
			if ev.Event == "erased" {
				renderAccountErased(w, ev)
			} else {
				renderSessionEnded(w, ev)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	renderAccount(w, sess, nil)
}

func renderSessionEnded(w http.ResponseWriter, ev *sessionEvent) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · session ended", "account", false)

	fmt.Fprint(w, `<div style="max-width:620px;margin:2rem auto 0"><div class="card">`)
	fmt.Fprintf(w, `<div class="card-head"><h1>You were signed out by TrustNet</h1><span class="badge warn">%s</span></div>`,
		html.EscapeString(ev.Event))
	fmt.Fprint(w, `<p>The demo RP session ended because TrustNet notified it server-to-server. Your browser cookie is no longer valid.</p>`)
	fmt.Fprint(w, `<dl class="kv" style="margin-top:1rem">`)
	fmt.Fprintf(w, `<dt>Event</dt><dd>%s</dd><dt>Received</dt><dd>%s</dd>`,
		html.EscapeString(eventLabel(ev.Event)), formatTime(ev.CreatedAt))
	if ev.Sub != "" {
		fmt.Fprintf(w, `<dt>sub</dt><dd class="mono">%s</dd>`, html.EscapeString(ev.Sub))
	}
	if ev.SID != "" {
		fmt.Fprintf(w, `<dt>sid</dt><dd class="mono">%s</dd>`, html.EscapeString(ev.SID))
	}
	fmt.Fprint(w, `</dl><div class="row" style="margin-top:1.2rem"><a class="btn" href="/">Log in again</a><a class="btn secondary" href="/webhooks">Open webhook log</a></div></div>`)
	fmt.Fprint(w, `<p class="muted" style="margin-top:1rem">This notice is shown once from the short-lived tombstone and disappears after the one-hour TTL.</p></div>`)
	pageEnd(w)
}

func renderAccountErased(w http.ResponseWriter, ev *sessionEvent) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · account erased", "account", false)

	fmt.Fprint(w, `<div style="max-width:620px;margin:2rem auto 0"><div class="card">`)
	fmt.Fprint(w, `<div class="card-head"><h1>Your demo RP data was erased</h1><span class="badge danger">account.erased</span></div>`)
	fmt.Fprint(w, `<p>TrustNet sent an account erasure webhook. This demo RP deleted its session and stored demo data for the affected subject.</p>`)
	fmt.Fprint(w, `<dl class="kv" style="margin-top:1rem">`)
	fmt.Fprint(w, `<dt>Event</dt><dd><code>account.erased</code></dd>`)
	fmt.Fprintf(w, `<dt>Reason</dt><dd><code>%s</code></dd>`, html.EscapeString(orDash(ev.Reason)))
	fmt.Fprintf(w, `<dt>Delivery</dt><dd class="mono">%s</dd>`, html.EscapeString(orDash(ev.DeliveryID)))
	fmt.Fprintf(w, `<dt>Received</dt><dd>%s</dd>`, formatTime(ev.CreatedAt))
	if ev.Sub != "" {
		fmt.Fprintf(w, `<dt>sub</dt><dd class="mono">%s</dd>`, html.EscapeString(ev.Sub))
	}
	fmt.Fprint(w, `</dl>`)
	fmt.Fprint(w, `<div class="notice" style="margin-top:1rem" role="status">The erasure was verified against TrustNet's Ed25519 JWKS before anything was deleted.</div>`)
	fmt.Fprint(w, `<div class="row" style="margin-top:1.2rem"><a class="btn" href="/">Start over</a><a class="btn secondary" href="/webhooks">Open webhook log</a></div></div>`)
	fmt.Fprint(w, `<p class="muted" style="margin-top:1rem">Unverified deliveries are recorded but never produce this screen or delete data.</p></div>`)
	pageEnd(w)
}

// GET /logout — clear the local session and return to the app's home screen.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, err := currentSession(r)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
		return
	}

	if sess != nil {
		if err := dataStore.deleteSession(sess.IDHash); err != nil {
			log.Printf("logout: delete session: %v", err)
		}
		if err := dataStore.recordSessionEvent(sessionEvent{
			SessionHash: sess.IDHash,
			Sub:         sess.Sub,
			SID:         sess.SID,
			Event:       "logged_out",
			Reason:      "rp_initiated",
			CreatedAt:   time.Now().UTC(),
		}); err != nil {
			log.Printf("logout: record event: %v", err)
		}
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startSession persists the successful flow and sets the demo cookie. Any
// previous cookie for this browser is replaced.
func startSession(w http.ResponseWriter, r *http.Request, f *flowState) (*session, error) {
	sub := claimString(f.IDClaims, "sub")
	if sub == "" {
		return nil, fmt.Errorf("ID token has no sub")
	}
	if dataStore == nil {
		return nil, fmt.Errorf("store is not initialized")
	}
	if old := sessionIDFromRequest(r); old != "" {
		_ = dataStore.deleteSession(hashSessionID(old))
	}

	id, hash := newSessionID()
	now := time.Now().UTC()
	x := session{
		IDHash:            hash,
		Sub:               sub,
		SID:               claimString(f.IDClaims, "sid"),
		PreferredUsername: claimString(f.IDClaims, "preferred_username"),
		IDToken:           tokenString(f, "id_token"),
		AccessToken:       tokenString(f, "access_token"),
		Claims:            f.IDClaims,
		UserInfo:          f.UserInfo,
		CreatedAt:         now,
		ExpiresAt:         now.Add(env.SessionTTL),
	}
	if x.PreferredUsername == "" {
		x.PreferredUsername = claimString(f.UserInfo, "preferred_username")
	}
	if err := dataStore.createSession(x); err != nil {
		return nil, err
	}
	setSessionCookie(w, id)
	if err := dataStore.recordSessionEvent(sessionEvent{
		SessionHash: hash,
		Sub:         sub,
		SID:         x.SID,
		Event:       "logged_in",
		CreatedAt:   now,
	}); err != nil {
		log.Printf("session: record login event: %v", err)
	}
	return &x, nil
}

func tokenString(f *flowState, key string) string {
	if f.TokenResp == nil {
		return ""
	}
	s, _ := f.TokenResp[key].(string)
	return s
}

func currentSession(r *http.Request) (*session, error) {
	id := sessionIDFromRequest(r)
	if id == "" || dataStore == nil {
		return nil, nil
	}
	return dataStore.sessionByID(hashSessionID(id))
}

func latestFlowForSub(sub string) *flowState {
	if sub == "" {
		return nil
	}
	flowsMu.Lock()
	defer flowsMu.Unlock()
	var newest *flowState
	for _, f := range flows {
		if claimString(f.IDClaims, "sub") != sub {
			continue
		}
		if newest == nil || f.CreatedAt.After(newest.CreatedAt) {
			newest = f
		}
	}
	return newest
}

func claimString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func displayName(s *session) string {
	if s.PreferredUsername != "" {
		return s.PreferredUsername
	}
	for _, key := range []string{"name", "email"} {
		if v := claimString(s.Claims, key); v != "" {
			return v
		}
	}
	if s.Sub != "" {
		return s.Sub
	}
	return "unknown user"
}

func avatarInitial(name string) string {
	for _, r := range name {
		if r == ' ' {
			continue
		}
		return strings.ToUpper(string(r))
	}
	return "?"
}

func relativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func untilTime(t time.Time) string {
	d := time.Until(t)
	switch {
	case d <= 0:
		return "expired"
	case d < time.Minute:
		return "in less than a minute"
	case d < 59*time.Minute:
		return fmt.Sprintf("in %dm", int(d.Minutes())+1)
	default:
		return fmt.Sprintf("in %dh", int(math.Ceil(d.Hours())))
	}
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func secureSuffix() string {
	if env.CookieSecure {
		return " · Secure"
	}
	return ""
}

func renderAccount(w http.ResponseWriter, sess *session, probe *machineProbe) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · account", "account", true)

	name := displayName(sess)
	fmt.Fprintf(w, `<section class="page-head"><div class="row spread"><div class="row"><span class="avatar" aria-hidden="true">%s</span><div><h1>Logged in as %s</h1><p class="muted">Session started %s · expires %s</p></div></div><a class="btn secondary" href="/logout">Sign out</a></div></section>`,
		html.EscapeString(avatarInitial(name)), html.EscapeString(name),
		html.EscapeString(relativeTime(sess.CreatedAt)), html.EscapeString(untilTime(sess.ExpiresAt)))

	latest := latestFlowForSub(sess.Sub)
	if probe == nil && latest != nil {
		probe = latest.MachineProbe
	}

	fmt.Fprint(w, `<div class="grid two">`)
	fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>Session</h2><span class="badge ok">active</span></div><dl class="kv">`)
	fmt.Fprintf(w, `<dt>sub (PPID)</dt><dd class="mono">%s</dd>`, html.EscapeString(sess.Sub))
	if sess.SID != "" {
		fmt.Fprintf(w, `<dt>sid</dt><dd class="mono">%s</dd>`, html.EscapeString(sess.SID))
	}
	fmt.Fprintf(w, `<dt>Started</dt><dd>%s</dd><dt>Expires</dt><dd>%s</dd>`, formatTime(sess.CreatedAt), formatTime(sess.ExpiresAt))
	fmt.Fprintf(w, `<dt>Cookie</dt><dd><code>%s</code> · HttpOnly · SameSite=Lax%s</dd>`, sessionCookieName, secureSuffix())
	fmt.Fprint(w, `</dl></section>`)

	fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>Identity from the ID token</h2><span class="badge accent">verified login</span></div><dl class="kv">`)
	renderClaimsKV(w, sess.Claims, map[string]bool{"sub": true})
	fmt.Fprint(w, `</dl></section></div>`)

	fmt.Fprint(w, `<div class="grid two" style="margin-top:1rem">`)
	fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>OIDC /userinfo</h2>`)
	if _, isErr := sess.UserInfo["error"]; isErr {
		fmt.Fprint(w, `<span class="badge danger">error</span>`)
	} else {
		fmt.Fprint(w, `<span class="badge accent">userinfo</span>`)
	}
	fmt.Fprint(w, `</div>`)
	if len(sess.UserInfo) == 0 {
		fmt.Fprint(w, `<p class="muted">No /userinfo response was returned.</p>`)
	} else {
		fmt.Fprintf(w, `<pre>%s</pre>`, html.EscapeString(pretty(sess.UserInfo)))
	}
	fmt.Fprint(w, `</section>`)

	if env.MachineURL != "" {
		fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>TrustNet machine-plane userinfo</h2><span class="badge accent">probe</span></div>`)
		if sess.AccessToken == "" {
			fmt.Fprint(w, `<p class="muted">No access token is stored for this session, so the machine-plane probe is unavailable.</p>`)
		} else {
			fmt.Fprint(w, `<p class="muted">Server-to-server read with the consent-time access token.</p>`)
			fmt.Fprint(w, `<form method="post" action="/rp-userinfo"><button class="btn secondary" type="submit">Test userinfo endpoint</button></form>`)
			if probe != nil {
				renderMachineProbe(w, probe)
			}
		}
		fmt.Fprint(w, `</section>`)
	}
	fmt.Fprint(w, `</div>`)

	fmt.Fprint(w, `<div class="grid two" style="margin-top:1rem">`)
	fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>Flow</h2><span class="badge">inspect</span></div>`)
	fmt.Fprint(w, `<p class="muted">The authorization request, token response, decoded claims, and machine probe.</p>`)
	fmt.Fprint(w, `<div class="row actions">`)
	if latest != nil {
		fmt.Fprintf(w, `<a class="btn" href="/result?state=%s">View last flow</a>`, url.QueryEscape(latest.State))
	}
	fmt.Fprint(w, `<a class="btn secondary" href="/start?preview=1">Preview request</a></div></section>`)

	fmt.Fprint(w, `<section class="card"><div class="card-head"><h2>Session events</h2><span class="badge">events</span></div>`)
	ev, err := dataStore.latestSessionEvent(sess)
	if err != nil {
		log.Printf("account: latest event: %v", err)
	}
	if ev == nil {
		fmt.Fprint(w, `<p class="muted">No TrustNet events for this session yet.</p>`)
	} else {
		fmt.Fprintf(w, `<dl class="kv"><dt>Event</dt><dd>%s</dd><dt>Received</dt><dd>%s</dd>`, html.EscapeString(eventLabel(ev.Event)), formatTime(ev.CreatedAt))
		if ev.Reason != "" {
			fmt.Fprintf(w, `<dt>Reason</dt><dd><code>%s</code></dd>`, html.EscapeString(ev.Reason))
		}
		fmt.Fprint(w, `</dl>`)
	}
	fmt.Fprint(w, `</section></div>`)

	fmt.Fprint(w, `<p class="footer-note">Sign out clears the demo session locally and returns you to the home screen.</p>`)
	pageEnd(w)
}

func renderClaimsKV(w http.ResponseWriter, claims map[string]any, skip map[string]bool) {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		if skip[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, `<dt>%s</dt><dd>%s</dd>`, html.EscapeString(k), html.EscapeString(claimValue(claims[k])))
	}
	if len(keys) == 0 {
		fmt.Fprint(w, `<dt>Claims</dt><dd class="muted">none</dd>`)
	}
}

func claimValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == math.Trunc(x) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case map[string]any, []any:
		return pretty(x)
	default:
		return fmt.Sprint(x)
	}
}

func eventLabel(event string) string {
	switch event {
	case "logged_out":
		return "Back-channel logout"
	case "revoked":
		return "Access revoked"
	case "erased":
		return "Account erased"
	default:
		return event
	}
}

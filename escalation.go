package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
)

// handleEscalate renders the escalation request form. Only a signed-in user can
// ask for additional claims; the actual authorize request is handled by
// /start?escalate=1.
func handleEscalate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "This action accepts GET only.")
		return
	}
	sess, err := currentSession(r)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Could not read the demo session.")
		return
	}
	if sess == nil {
		renderError(w, http.StatusUnauthorized, "A valid session is required to escalate claims.")
		return
	}
	renderEscalationRequest(w, sess)
}

func renderEscalationRequest(w http.ResponseWriter, sess *session) {
	prior := sessionRequestableClaimNames(sess)
	available := claimNamesDifference(requestableClaims, prior)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · escalate", "escalate", true)

	fmt.Fprint(w, `<section class="page-head">
<p class="eyebrow">Consent escalation</p>
<h1>Request more claims from TrustNet</h1>
<p class="lede">Your current session already shares the claims listed below. Select
the additional claims you want TrustNet to review, then continue. TrustNet will
show a full consent review before sharing anything new.</p>
</section>`)

	fmt.Fprint(w, `<div class="notice" role="note"><span class="notice-icon" aria-hidden="true">i</span><span>This sends a new authorization request to TrustNet. The claims already shared with this RP are carried over; only the new claims need review.</span></div>`)

	fmt.Fprint(w, `<section class="card" style="margin-top:1rem"><div class="card-head"><h2>Already shared</h2><span class="badge ok">carried over</span></div>`)
	fmt.Fprint(w, `<p class="muted">These claim names are present in the current session. They are included in the escalation request automatically and cannot be deselected here.</p>`)
	if len(prior) == 0 {
		fmt.Fprint(w, `<p class="muted">No requestable claims are currently shared.</p>`)
	} else {
		fmt.Fprint(w, `<div class="row" style="margin-top:.7rem">`)
		for _, name := range prior {
			fmt.Fprintf(w, `<span class="badge" data-claim="%s">%s</span>`, html.EscapeString(name), html.EscapeString(name))
		}
		fmt.Fprint(w, `</div>`)
	}
	fmt.Fprint(w, `</section>`)

	if len(available) == 0 {
		fmt.Fprint(w, `<section class="card" style="margin-top:1rem"><div class="card-head"><h2>Request additional claims</h2><span class="badge">complete</span></div><p class="muted">Every available claim is already shared with this RP.</p></section>`)
		fmt.Fprint(w, `<div class="row actions"><a class="btn secondary" href="/account">Cancel</a></div>`)
		fmt.Fprint(w, `<p class="footer-note">No escalation request can be started while every available claim is already shared.</p>`)
		pageEnd(w)
		return
	}

	fmt.Fprint(w, `<form method="get" action="/start"><input type="hidden" name="escalate" value="1"><input type="hidden" name="prompt" value="consent"><input type="hidden" name="scope" value="openid">`)
	for _, name := range prior {
		fmt.Fprintf(w, `<input type="hidden" name="claim" value="%s">`, html.EscapeString(name))
	}
	fmt.Fprint(w, `<fieldset class="panel" style="margin-top:1rem"><legend class="sr-only">Request additional claims</legend><div class="panel-head" aria-hidden="true"><span class="panel-title">Request additional claims</span><span class="panel-meta">not already shared</span></div><p class="hint">Select the new claims you want TrustNet to review. Previously shared claims are carried over automatically.</p><div class="checks claim-grid">`)
	for _, name := range available {
		fmt.Fprintf(w, `<label class="check tile"><input type="checkbox" name="claim" value="%s"> <span>%s</span></label>`,
			html.EscapeString(name), html.EscapeString(name))
	}
	fmt.Fprint(w, `</div></fieldset>`)
	fmt.Fprint(w, `<div class="row actions"><button class="btn" type="submit" data-testid="escalate-submit">Continue to TrustNet</button><a class="btn secondary" href="/account">Cancel</a></div></form>`)
	fmt.Fprint(w, `<p class="footer-note">After TrustNet returns, the flow result reports which requested claims were shared and which were not returned.</p>`)
	pageEnd(w)
}

// requestableClaimNames filters arbitrary submitted names to the known catalog
// and returns them in the catalog's stable order.
func requestableClaimNames(names []string) []string {
	want := map[string]bool{}
	for _, name := range names {
		want[name] = true
	}
	out := make([]string, 0, len(want))
	for _, name := range requestableClaims {
		if want[name] {
			out = append(out, name)
		}
	}
	return out
}

// sessionRequestableClaimNames returns the requestable claims the session
// already holds, from either the ID token or /userinfo.
func sessionRequestableClaimNames(sess *session) []string {
	present := map[string]bool{}
	for _, m := range []map[string]any{sess.Claims, sess.UserInfo} {
		for name, v := range m {
			if v != nil {
				present[name] = true
			}
		}
	}
	out := make([]string, 0, len(present))
	for _, name := range requestableClaims {
		if present[name] {
			out = append(out, name)
		}
	}
	return out
}

// claimNamesDifference returns the names in a that are not in b, preserving a's
// order.
func claimNamesDifference(a, b []string) []string {
	skip := map[string]bool{}
	for _, name := range b {
		skip[name] = true
	}
	out := make([]string, 0, len(a))
	for _, name := range a {
		if !skip[name] {
			out = append(out, name)
		}
	}
	return out
}

// unionClaimNames returns the catalog-ordered union of both sets.
func unionClaimNames(a, b []string) []string {
	want := map[string]bool{}
	for _, name := range a {
		want[name] = true
	}
	for _, name := range b {
		want[name] = true
	}
	out := make([]string, 0, len(want))
	for _, name := range requestableClaims {
		if want[name] {
			out = append(out, name)
		}
	}
	return out
}

// claimsParamJSON builds the voluntary id_token claims request. A nil value asks
// for the claim without making it essential.
func claimsParamJSON(names []string) string {
	if len(names) == 0 {
		return ""
	}
	m := map[string]any{}
	for _, name := range names {
		m[name] = nil
	}
	b, _ := json.Marshal(map[string]any{"id_token": m})
	return string(b)
}

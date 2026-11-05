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
	"strings"
	"sync"
	"time"
)

const jwksTTL = 5 * time.Minute

var (
	jwksMu      sync.Mutex
	jwksKeys    map[string]ed25519.PublicKey
	jwksFetched time.Time
)

// POST /purge — TrustNet delivers a signed revocation or erasure. The compact
// JWS is verified against the cached JWKS, the payload is validated, and only
// verified, well-formed deliveries act on sessions.
func handlePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	rec := webhookRecord{ReceivedAt: time.Now().UTC(), BodyLen: len(body)}

	var payload map[string]any
	switch {
	case env.JWKSURL == "":
		rec.Error = "JWKS_URL not configured"
	default:
		p, kid, err := verifyWebhookJWS(string(body))
		if err != nil {
			rec.Error = err.Error()
		} else {
			rec.Verified = true
			rec.Kid = kid
			rec.Payload = p
			payload = p
		}
	}

	var event, reason, deliveryID string
	var subs []string
	if payload != nil {
		var err error
		event, reason, deliveryID, subs, err = validatePurgePayload(payload)
		if err != nil {
			rec.Error = "payload: " + err.Error()
		}
	}

	if dataStore != nil {
		if err := dataStore.recordWebhook(rec); err != nil {
			log.Printf("purge: record delivery: %v", err)
		}
	}

	if rec.Verified && rec.Error == "" {
		now := time.Now().UTC()
		tombstone := "revoked"
		if event == "account.erased" {
			tombstone = "erased"
		}
		for _, sub := range subs {
			hashes, err := dataStore.deleteSessionsForLogout("", sub)
			if err != nil {
				log.Printf("purge: delete sessions: %v", err)
				continue
			}
			for _, h := range hashes {
				if err := dataStore.recordSessionEvent(sessionEvent{
					SessionHash: h,
					Sub:         sub,
					Event:       tombstone,
					Reason:      reason,
					DeliveryID:  deliveryID,
					CreatedAt:   now,
				}); err != nil {
					log.Printf("purge: record event: %v", err)
				}
			}
			if event == "account.erased" {
				deleteFlowsBySub(sub)
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	if env.PurgeStrict {
		http.Error(w, rec.Error, http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// GET /debug/purge — machine-readable purge deliveries.
func handleDebugPurge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	var deliveries []webhookRecord
	if dataStore != nil {
		var err error
		deliveries, err = dataStore.recentWebhooks(100)
		if err != nil {
			http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if deliveries == nil {
		deliveries = []webhookRecord{}
	}
	json.NewEncoder(w).Encode(map[string]any{"purge_deliveries": deliveries})
}

// GET /webhooks — public proof that server-to-server notifications arrived.
func handleWebhooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	pageStart(w, "OIDC · webhooks", "webhooks")

	fmt.Fprint(w, `<section class="page-head"><div class="row spread"><div><h1>Webhook deliveries</h1><p class="muted">TrustNet signs each purge webhook with Ed25519. Verified rows were checked against the JWKS; invalid rows are recorded but not acted on.</p></div><div class="row"><a class="btn secondary small" href="/webhooks">Refresh</a><form method="post" action="/debug/reset"><input type="hidden" name="next" value="/webhooks"><button class="btn secondary small" type="submit">Reset demo state</button></form><a class="btn small" href="/debug/purge">Open JSON</a></div></div></section>`)

	var deliveries []webhookRecord
	var events []sessionEvent
	if dataStore != nil {
		var err error
		deliveries, err = dataStore.recentWebhooks(100)
		if err != nil {
			log.Printf("webhooks: deliveries: %v", err)
		}
		events, err = dataStore.recentLogoutEvents(100)
		if err != nil {
			log.Printf("webhooks: logout events: %v", err)
		}
	}

	if len(deliveries) > 0 {
		fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>Purge deliveries</h2><span class="badge">%d rows</span></div><table><thead><tr><th>Received</th><th>Event</th><th>Reason</th><th>Verified</th><th>Delivery</th><th>subs</th><th>Error</th></tr></thead><tbody>`, len(deliveries))
		for _, d := range deliveries {
			badge := `<span class="badge ok">verified</span>`
			if !d.Verified {
				badge = `<span class="badge danger">unverified</span>`
			}
			fmt.Fprintf(w, `<tr><td class="nowrap">%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="muted">%s</td></tr>`,
				html.EscapeString(shortTime(d.ReceivedAt)),
				html.EscapeString(orDash(payloadString(d.Payload, "event"))),
				html.EscapeString(orDash(payloadString(d.Payload, "reason"))),
				badge,
				html.EscapeString(orDash(payloadString(d.Payload, "delivery_id"))),
				html.EscapeString(orDash(strings.Join(payloadStrings(d.Payload["subs"]), ", "))),
				html.EscapeString(d.Error))
		}
		fmt.Fprint(w, `</tbody></table></section>`)
	}

	if len(events) > 0 {
		fmt.Fprintf(w, `<section class="card" style="margin-top:1rem"><div class="card-head"><h2>Back-channel logout events</h2><span class="badge">%d rows</span></div><table><thead><tr><th>Received</th><th>sid</th><th>sub</th><th>Event</th></tr></thead><tbody>`, len(events))
		for _, e := range events {
			fmt.Fprintf(w, `<tr><td class="nowrap">%s</td><td class="mono">%s</td><td class="mono">%s</td><td><span class="badge ok">%s</span></td></tr>`,
				html.EscapeString(shortTime(e.CreatedAt)),
				html.EscapeString(orDash(e.SID)),
				html.EscapeString(orDash(e.Sub)),
				html.EscapeString(e.Event))
		}
		fmt.Fprint(w, `</tbody></table></section>`)
	}

	if len(deliveries) == 0 && len(events) == 0 {
		fmt.Fprint(w, `<section class="card"><div class="empty">No deliveries yet. Revoke access or erase an account in TrustNet, then refresh.</div></section>`)
	}

	fmt.Fprint(w, `<p class="footer-note">This page is public and contains only PPIDs and delivery metadata — never tokens, cookies, or claim values.</p>`)
	pageEnd(w)
}

func shortTime(t time.Time) string {
	return t.UTC().Format("15:04:05 UTC")
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func payloadString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func payloadStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}

func validatePurgePayload(payload map[string]any) (event, reason, deliveryID string, subs []string, err error) {
	event = payloadString(payload, "event")
	switch event {
	case "access.revoked", "account.erased":
	default:
		return "", "", "", nil, fmt.Errorf("unsupported event %q", event)
	}
	if clientID := payloadString(payload, "client_id"); clientID != env.ClientID {
		return "", "", "", nil, fmt.Errorf("client_id does not match")
	}
	reason = payloadString(payload, "reason")
	if reason == "" {
		return "", "", "", nil, fmt.Errorf("reason is missing")
	}
	deliveryID = payloadString(payload, "delivery_id")
	if deliveryID == "" {
		return "", "", "", nil, fmt.Errorf("delivery_id is missing")
	}
	subs = payloadStrings(payload["subs"])
	if len(subs) == 0 {
		return "", "", "", nil, fmt.Errorf("subs is missing")
	}
	return event, reason, deliveryID, subs, nil
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

// jwksKey returns the Ed25519 public key for kid, refreshing the cached JWKS
// when it is stale or the kid is unknown.
func jwksKey(kid string) (ed25519.PublicKey, error) {
	jwksMu.Lock()
	defer jwksMu.Unlock()

	if time.Since(jwksFetched) < jwksTTL {
		if key, ok := jwksKeys[kid]; ok {
			return key, nil
		}
	}
	if err := refreshJWKSLocked(); err != nil {
		if key, ok := jwksKeys[kid]; ok {
			// Keep serving a previously fetched key when the JWKS is temporarily
			// unavailable.
			return key, nil
		}
		return nil, err
	}
	if key, ok := jwksKeys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}

func refreshJWKSLocked() error {
	resp, err := httpc.Get(env.JWKSURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	next := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		next[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(next) == 0 {
		return fmt.Errorf("JWKS has no usable Ed25519 keys")
	}
	jwksKeys = next
	jwksFetched = time.Now()
	return nil
}

package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

// sessionCookieName is the demo's own cookie. The value is a random id; only
// its SHA-256 hash is stored, so a database leak cannot be replayed as a
// session.
const sessionCookieName = "demo_rp_session"

// dataStore is opened once at startup and shared by the handlers.
var dataStore *store

// store is the SQLite-backed demo state: sessions, their lifecycle events, and
// received webhook deliveries. Everything is pruned by the sweeper.
type store struct {
	db  *sql.DB
	ttl time.Duration
}

// session is one logged-in demo visitor. Tokens are kept for the session's
// one-hour lifetime so logout can send id_token_hint and the machine-plane
// probe survives a restart.
type session struct {
	IDHash            string
	Sub               string
	SID               string
	PreferredUsername string
	IDToken           string
	AccessToken       string
	Claims            map[string]any
	UserInfo          map[string]any
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// sessionEvent is an append-only lifecycle record (logged in, logged out,
// revoked, erased).
type sessionEvent struct {
	SessionHash string
	Sub         string
	SID         string
	Event       string
	Reason      string
	DeliveryID  string
	CreatedAt   time.Time
}

// webhookRecord is one received purge delivery.
type webhookRecord struct {
	ReceivedAt time.Time      `json:"received_at"`
	Verified   bool           `json:"verified"`
	Kid        string         `json:"kid,omitempty"`
	Error      string         `json:"error,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
	BodyLen    int            `json:"body_len"`
}

func openStore(path string, ttl time.Duration) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer at a time; a single connection also removes
	// most "database is locked" surprises in this single-instance demo.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("busy_timeout: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("journal_mode: %w", err)
	}

	s := &store{db: db, ttl: ttl}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) Close() error { return s.db.Close() }

func (s *store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id_hash            TEXT PRIMARY KEY,
			sub                TEXT NOT NULL DEFAULT '',
			sid                TEXT NOT NULL DEFAULT '',
			preferred_username TEXT NOT NULL DEFAULT '',
			id_token           TEXT NOT NULL DEFAULT '',
			access_token       TEXT NOT NULL DEFAULT '',
			claims_json        TEXT NOT NULL DEFAULT '{}',
			userinfo_json      TEXT NOT NULL DEFAULT '{}',
			created_at         INTEGER NOT NULL,
			expires_at         INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_sub ON sessions(sub)`,
		`CREATE TABLE IF NOT EXISTS session_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			session_hash TEXT NOT NULL DEFAULT '',
			sub          TEXT NOT NULL DEFAULT '',
			sid          TEXT NOT NULL DEFAULT '',
			event        TEXT NOT NULL,
			reason       TEXT NOT NULL DEFAULT '',
			delivery_id  TEXT NOT NULL DEFAULT '',
			created_at   INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_session_events_created ON session_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			received_at  INTEGER NOT NULL,
			verified     INTEGER NOT NULL DEFAULT 0,
			kid          TEXT NOT NULL DEFAULT '',
			error        TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL DEFAULT '{}',
			body_len     INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_received ON webhook_deliveries(received_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// prune drops expired sessions and state older than the session TTL.
func (s *store) prune(now time.Time) error {
	cutoff := now.Add(-s.ttl).Unix()
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM session_events WHERE created_at <= ?`, cutoff); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM webhook_deliveries WHERE received_at <= ?`, cutoff); err != nil {
		return err
	}
	return nil
}

// startSweeper prunes the database and stale in-memory flows on an interval.
func (s *store) startSweeper(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for now := range t.C {
			if err := s.prune(now.UTC()); err != nil {
				log.Printf("store sweep: %v", err)
			}
			pruneOldFlows(s.ttl)
		}
	}()
}

func pruneOldFlows(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	flowsMu.Lock()
	defer flowsMu.Unlock()
	for state, f := range flows {
		if f.CreatedAt.Before(cutoff) {
			delete(flows, state)
		}
	}
}

func (s *store) createSession(x session) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO sessions
		(id_hash, sub, sid, preferred_username, id_token, access_token,
		 claims_json, userinfo_json, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		x.IDHash, x.Sub, x.SID, x.PreferredUsername, x.IDToken, x.AccessToken,
		encodeMap(x.Claims), encodeMap(x.UserInfo), x.CreatedAt.Unix(), x.ExpiresAt.Unix())
	return err
}

func (s *store) sessionByID(idHash string) (*session, error) {
	var x session
	var claims, userinfo string
	var created, expires int64
	err := s.db.QueryRow(`SELECT id_hash, sub, sid, preferred_username, id_token,
		access_token, claims_json, userinfo_json, created_at, expires_at
		FROM sessions WHERE id_hash = ?`, idHash).
		Scan(&x.IDHash, &x.Sub, &x.SID, &x.PreferredUsername, &x.IDToken,
			&x.AccessToken, &claims, &userinfo, &created, &expires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	x.Claims = decodeMap(claims)
	x.UserInfo = decodeMap(userinfo)
	x.CreatedAt = time.Unix(created, 0).UTC()
	x.ExpiresAt = time.Unix(expires, 0).UTC()
	if !x.ExpiresAt.After(time.Now()) {
		_ = s.deleteSession(idHash)
		return nil, nil
	}
	return &x, nil
}

func (s *store) deleteSession(idHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

func (s *store) deleteSessionsBySID(sid string) (int64, error) {
	if sid == "" {
		return 0, nil
	}
	res, err := s.db.Exec(`DELETE FROM sessions WHERE sid = ?`, sid)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *store) deleteSessionsBySub(sub string) (int64, error) {
	if sub == "" {
		return 0, nil
	}
	res, err := s.db.Exec(`DELETE FROM sessions WHERE sub = ?`, sub)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *store) recordSessionEvent(e sessionEvent) error {
	_, err := s.db.Exec(`INSERT INTO session_events
		(session_hash, sub, sid, event, reason, delivery_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.SessionHash, e.Sub, e.SID, e.Event, e.Reason, e.DeliveryID, e.CreatedAt.Unix())
	return err
}

// deleteSessionsForLogout removes sessions matching sid first, then sub when no
// sid match exists. It returns the id hashes it deleted so the caller can write
// one tombstone per stale cookie.
func (s *store) deleteSessionsForLogout(sid, sub string) ([]string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	hashes, err := sessionHashes(tx, "sid", sid)
	if err != nil {
		return nil, err
	}
	if len(hashes) == 0 && sub != "" {
		hashes, err = sessionHashes(tx, "sub", sub)
		if err != nil {
			return nil, err
		}
	}
	for _, h := range hashes {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE id_hash = ?`, h); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return hashes, nil
}

func sessionHashes(tx *sql.Tx, column, value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	if column != "sid" && column != "sub" {
		return nil, fmt.Errorf("unsupported session column %q", column)
	}
	rows, err := tx.Query(`SELECT id_hash FROM sessions WHERE `+column+` = ?`, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

// tombstoneByIDHash resolves a stale browser cookie to the newest
// logout/revoke/erase event recorded for that session.
func (s *store) tombstoneByIDHash(idHash string) (*sessionEvent, error) {
	if idHash == "" {
		return nil, nil
	}
	var e sessionEvent
	var created int64
	err := s.db.QueryRow(`SELECT session_hash, sub, sid, event, reason, delivery_id, created_at
		FROM session_events
		WHERE session_hash = ? AND event IN ('logged_out', 'revoked', 'erased')
		ORDER BY created_at DESC LIMIT 1`, idHash).
		Scan(&e.SessionHash, &e.Sub, &e.SID, &e.Event, &e.Reason, &e.DeliveryID, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.CreatedAt = time.Unix(created, 0).UTC()
	return &e, nil
}

// latestSessionEvent returns the newest logout/revoke/erase event that applies
// to a session. Login events are deliberately excluded.
func (s *store) latestSessionEvent(x *session) (*sessionEvent, error) {
	var e sessionEvent
	var created int64
	err := s.db.QueryRow(`SELECT session_hash, sub, sid, event, reason, delivery_id, created_at
		FROM session_events
		WHERE event IN ('logged_out', 'revoked', 'erased')
		  AND (session_hash = ? OR (sub != '' AND sub = ?) OR (sid != '' AND sid = ?))
		ORDER BY created_at DESC LIMIT 1`,
		x.IDHash, x.Sub, x.SID).
		Scan(&e.SessionHash, &e.Sub, &e.SID, &e.Event, &e.Reason, &e.DeliveryID, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.CreatedAt = time.Unix(created, 0).UTC()
	return &e, nil
}

// reset drops every persisted demo row. It is used by /debug/reset.
func (s *store) reset() error {
	for _, q := range []string{
		`DELETE FROM sessions`,
		`DELETE FROM session_events`,
		`DELETE FROM webhook_deliveries`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) recordWebhook(d webhookRecord) error {
	_, err := s.db.Exec(`INSERT INTO webhook_deliveries
		(received_at, verified, kid, error, payload_json, body_len)
		VALUES (?, ?, ?, ?, ?, ?)`,
		d.ReceivedAt.Unix(), boolInt(d.Verified), d.Kid, d.Error,
		encodeMap(d.Payload), d.BodyLen)
	return err
}

func (s *store) recentWebhooks(limit int) ([]webhookRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT received_at, verified, kid, error, payload_json, body_len
		FROM webhook_deliveries ORDER BY received_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []webhookRecord
	for rows.Next() {
		var d webhookRecord
		var received int64
		var verified int
		var payload string
		if err := rows.Scan(&received, &verified, &d.Kid, &d.Error, &payload, &d.BodyLen); err != nil {
			return nil, err
		}
		d.ReceivedAt = time.Unix(received, 0).UTC()
		d.Verified = verified != 0
		d.Payload = decodeMap(payload)
		out = append(out, d)
	}
	return out, rows.Err()
}

// recentLogoutEvents lists verified back-channel logout deliveries for the
// /webhooks page. Purge events are listed from webhook_deliveries instead.
func (s *store) recentLogoutEvents(limit int) ([]sessionEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT session_hash, sub, sid, event, reason, delivery_id, created_at
		FROM session_events
		WHERE event = 'logged_out' AND reason = 'backchannel_logout'
		ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []sessionEvent
	for rows.Next() {
		var e sessionEvent
		var created int64
		if err := rows.Scan(&e.SessionHash, &e.Sub, &e.SID, &e.Event, &e.Reason, &e.DeliveryID, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func encodeMap(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeMap(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	return m
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// --- session cookie helpers --------------------------------------------------

// newSessionID returns the cookie value and the hash that is persisted.
func newSessionID() (id, hash string) {
	id = randB64(32)
	return id, hashSessionID(id)
}

func hashSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   env.CookieSecure,
		MaxAge:   int(env.SessionTTL.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   env.CookieSecure,
		MaxAge:   -1,
	})
}

func sessionIDFromRequest(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

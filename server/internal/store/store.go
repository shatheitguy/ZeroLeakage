// Package store persists settings, users, devices, rules and the query log in SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the database.
type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'lan',
  ips TEXT NOT NULL DEFAULT '',
  token_hash TEXT,
  paused INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rules (
  scope TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('allow','block')),
  domain TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, kind, domain)
);
CREATE TABLE IF NOT EXISTS custom_lists (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'Custom'
);
CREATE TABLE IF NOT EXISTS querylog (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  client TEXT NOT NULL,
  device_id TEXT NOT NULL DEFAULT '',
  qname TEXT NOT NULL,
  qtype TEXT NOT NULL,
  blocked INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  list TEXT NOT NULL DEFAULT '',
  upstream TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER NOT NULL DEFAULT 0,
  rcode TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS querylog_ts ON querylog(ts);
`

// Open opens (and migrates) dataDir/zeroleakage.db.
func Open(dataDir string) (*Store, error) {
	dsn := "file:" + filepath.Join(dataDir, "zeroleakage.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ───────────────────────── settings ─────────────────────────

// Settings is the server-wide configuration (stored as JSON).
type Settings struct {
	EnabledLists   []string `json:"enabledLists"`
	Upstream       string   `json:"upstream"`       // resolver id or custom https URL
	PlainFallback  []string `json:"plainFallback"`  // e.g. ["192.168.1.1:53"]
	BlockMode      string   `json:"blockMode"`      // "nxdomain" | "null_ip"
	AllowSignup    bool     `json:"allowSignup"`    // let people create accounts on the dashboard
	RetentionDays  int      `json:"retentionDays"`  // query log
	LogQueries     bool     `json:"logQueries"`
	PublicHostname string   `json:"publicHostname"` // e.g. dns.example.com (for DoH/DoT links)
}

func DefaultSettings(lists []string) Settings {
	return Settings{EnabledLists: lists, Upstream: "cloudflare", BlockMode: "nxdomain", RetentionDays: 7, LogQueries: true}
}

func (s *Store) GetSettings(def Settings) (Settings, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key='server'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return def, s.PutSettings(def)
	}
	if err != nil {
		return def, err
	}
	out := def
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return def, err
	}
	return out, nil
}

func (s *Store) PutSettings(v Settings) error {
	b, _ := json.Marshal(v)
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES('server',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(b))
	return err
}

// ───────────────────────── users & sessions ─────────────────────────

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	IsAdmin   bool   `json:"isAdmin"`
	CreatedAt int64  `json:"createdAt"`
	passHash  string
}

func (u User) PassHash() string { return u.passHash }

func (s *Store) UserCount() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
}

func (s *Store) CreateUser(username, passHash string, admin bool) (User, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO users(username,pass_hash,is_admin,created_at) VALUES(?,?,?,?)`, username, passHash, admin, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, errors.New("that username is taken")
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: username, IsAdmin: admin, CreatedAt: now, passHash: passHash}, nil
}

func (s *Store) scanUser(row *sql.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.passHash, &u.IsAdmin, &u.CreatedAt)
	return u, err
}

func (s *Store) UserByName(name string) (User, error) {
	return s.scanUser(s.db.QueryRow(`SELECT id,username,pass_hash,is_admin,created_at FROM users WHERE username=?`, name))
}

func (s *Store) UserByID(id int64) (User, error) {
	return s.scanUser(s.db.QueryRow(`SELECT id,username,pass_hash,is_admin,created_at FROM users WHERE id=?`, id))
}

func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT id,username,is_admin,created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// NewSession returns a fresh session token (only its hash is stored).
func (s *Store) NewSession(userID int64, ttl time.Duration) (string, error) {
	tok := RandomToken(32)
	_, err := s.db.Exec(`INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)`, HashToken(tok), userID, time.Now().Add(ttl).Unix())
	return tok, err
}

func (s *Store) SessionUser(tok string) (User, error) {
	return s.scanUser(s.db.QueryRow(`SELECT u.id,u.username,u.pass_hash,u.is_admin,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=? AND s.expires_at>?`, HashToken(tok), time.Now().Unix()))
}

func (s *Store) DeleteSession(tok string) { _, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, HashToken(tok)) }

// ───────────────────────── devices ─────────────────────────

type Device struct {
	ID        string   `json:"id"`
	UserID    *int64   `json:"userId,omitempty"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"` // "lan" (matched by IP) or "app" (DoH/DoT/linked app)
	IPs       []string `json:"ips"`
	Paused    bool     `json:"paused"`
	CreatedAt int64    `json:"createdAt"`
	LastSeen  int64    `json:"lastSeen"`
	Linked    bool     `json:"linked"` // has an app token
}

const deviceCols = `id,user_id,name,kind,ips,paused,created_at,last_seen,token_hash IS NOT NULL`

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var uid sql.NullInt64
	var ips string
	if err := sc.Scan(&d.ID, &uid, &d.Name, &d.Kind, &ips, &d.Paused, &d.CreatedAt, &d.LastSeen, &d.Linked); err != nil {
		return d, err
	}
	if uid.Valid {
		d.UserID = &uid.Int64
	}
	d.IPs = splitList(ips)
	return d, nil
}

func (s *Store) Devices(userID *int64) ([]Device, error) {
	q := `SELECT ` + deviceCols + ` FROM devices`
	var args []any
	if userID != nil {
		q += ` WHERE user_id=?`
		args = append(args, *userID)
	}
	rows, err := s.db.Query(q+` ORDER BY created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) Device(id string) (Device, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE id=?`, id))
}

// CreateDevice makes a device with a fresh short id (used in DoH paths and DoT hostnames).
func (s *Store) CreateDevice(userID *int64, name, kind string, ips []string) (Device, error) {
	d := Device{ID: NewDeviceID(), UserID: userID, Name: name, Kind: kind, IPs: ips, CreatedAt: time.Now().Unix()}
	_, err := s.db.Exec(`INSERT INTO devices(id,user_id,name,kind,ips,created_at) VALUES(?,?,?,?,?,?)`,
		d.ID, nullable(userID), name, kind, strings.Join(ips, ","), d.CreatedAt)
	return d, err
}

func (s *Store) UpdateDevice(d Device) error {
	_, err := s.db.Exec(`UPDATE devices SET name=?, ips=?, paused=? WHERE id=?`, d.Name, strings.Join(d.IPs, ","), d.Paused, d.ID)
	return err
}

func (s *Store) DeleteDevice(id string) error {
	_, err := s.db.Exec(`DELETE FROM devices WHERE id=?`, id)
	_, _ = s.db.Exec(`DELETE FROM rules WHERE scope=?`, "device:"+id)
	return err
}

// LinkDevice issues an app token for the device; the raw token is returned once.
func (s *Store) LinkDevice(id string) (string, error) {
	tok := RandomToken(32)
	res, err := s.db.Exec(`UPDATE devices SET token_hash=?, kind='app' WHERE id=?`, HashToken(tok), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sql.ErrNoRows
	}
	return tok, nil
}

func (s *Store) DeviceByToken(tok string) (Device, error) {
	return scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE token_hash=?`, HashToken(tok)))
}

func (s *Store) TouchDevices(lastSeen map[string]int64) {
	for id, ts := range lastSeen {
		_, _ = s.db.Exec(`UPDATE devices SET last_seen=? WHERE id=? AND last_seen<?`, ts, id, ts)
	}
}

// ───────────────────────── rules (with tombstones for sync) ─────────────────────────

// Rule is one allow/block domain in a scope: "default", "user:<id>" or "device:<id>".
type Rule struct {
	Kind      string `json:"kind"`
	Domain    string `json:"domain"`
	UpdatedAt int64  `json:"updatedAt"` // unix millis
	Deleted   bool   `json:"deleted,omitempty"`
}

func (s *Store) Rules(scope string, includeDeleted bool) ([]Rule, error) {
	q := `SELECT kind,domain,updated_at,deleted FROM rules WHERE scope=?`
	if !includeDeleted {
		q += ` AND deleted=0`
	}
	rows, err := s.db.Query(q+` ORDER BY kind,domain`, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.Kind, &r.Domain, &r.UpdatedAt, &r.Deleted); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MergeRules applies changes with per-item last-writer-wins; returns how many changed.
func (s *Store) MergeRules(scope string, changes []Rule) (int, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, r := range changes {
		if r.Kind != "allow" && r.Kind != "block" {
			continue
		}
		res, err := tx.Exec(`INSERT INTO rules(scope,kind,domain,updated_at,deleted) VALUES(?,?,?,?,?)
			ON CONFLICT(scope,kind,domain) DO UPDATE SET updated_at=excluded.updated_at, deleted=excluded.deleted
			WHERE excluded.updated_at > rules.updated_at`, scope, r.Kind, r.Domain, r.UpdatedAt, r.Deleted)
		if err != nil {
			return n, err
		}
		if c, _ := res.RowsAffected(); c > 0 {
			n++
		}
	}
	return n, tx.Commit()
}

// SetRule adds (or tombstones) one rule now.
func (s *Store) SetRule(scope, kind, domain string, deleted bool) error {
	_, err := s.MergeRules(scope, []Rule{{Kind: kind, Domain: domain, UpdatedAt: time.Now().UnixMilli(), Deleted: deleted}})
	return err
}

// RuleSets returns live allow/block sets for a scope.
func (s *Store) RuleSets(scope string) (allow, block map[string]bool, err error) {
	rs, err := s.Rules(scope, false)
	allow, block = map[string]bool{}, map[string]bool{}
	for _, r := range rs {
		if r.Kind == "allow" {
			allow[r.Domain] = true
		} else {
			block[r.Domain] = true
		}
	}
	return
}

// ───────────────────────── custom lists ─────────────────────────

type CustomList struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category"`
}

func (s *Store) CustomLists() ([]CustomList, error) {
	rows, err := s.db.Query(`SELECT id,name,url,category FROM custom_lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomList
	for rows.Next() {
		var c CustomList
		if err := rows.Scan(&c.ID, &c.Name, &c.URL, &c.Category); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) AddCustomList(c CustomList) error {
	_, err := s.db.Exec(`INSERT INTO custom_lists(id,name,url,category) VALUES(?,?,?,?)`, c.ID, c.Name, c.URL, c.Category)
	return err
}

func (s *Store) DeleteCustomList(id string) error {
	_, err := s.db.Exec(`DELETE FROM custom_lists WHERE id=?`, id)
	return err
}

// ───────────────────────── query log ─────────────────────────

type QueryEntry struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"` // unix millis
	Client    string `json:"client"`
	DeviceID  string `json:"deviceId"`
	QName     string `json:"qname"`
	QType     string `json:"qtype"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason"`
	List      string `json:"list"`
	Upstream  string `json:"upstream"`
	LatencyMs int64  `json:"latencyMs"`
	RCode     string `json:"rcode"`
}

func (s *Store) InsertQueries(batch []QueryEntry) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO querylog(ts,client,device_id,qname,qtype,blocked,reason,list,upstream,latency_ms,rcode) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, q := range batch {
		if _, err := st.Exec(q.TS, q.Client, q.DeviceID, q.QName, q.QType, q.Blocked, q.Reason, q.List, q.Upstream, q.LatencyMs, q.RCode); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryFilter narrows the query log.
type QueryFilter struct {
	DeviceID string
	Blocked  *bool
	Search   string
	Limit    int
	BeforeID int64
}

func (s *Store) Queries(f QueryFilter) ([]QueryEntry, error) {
	q := `SELECT id,ts,client,device_id,qname,qtype,blocked,reason,list,upstream,latency_ms,rcode FROM querylog WHERE 1=1`
	var args []any
	if f.DeviceID != "" {
		q += ` AND device_id=?`
		args = append(args, f.DeviceID)
	}
	if f.Blocked != nil {
		q += ` AND blocked=?`
		args = append(args, *f.Blocked)
	}
	if f.Search != "" {
		q += ` AND (qname LIKE ? OR client LIKE ?)`
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	if f.BeforeID > 0 {
		q += ` AND id<?`
		args = append(args, f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q += fmt.Sprintf(` ORDER BY id DESC LIMIT %d`, f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueryEntry
	for rows.Next() {
		var e QueryEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.DeviceID, &e.QName, &e.QType, &e.Blocked, &e.Reason, &e.List, &e.Upstream, &e.LatencyMs, &e.RCode); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Stats summarises the query log since a time.
type Stats struct {
	Total      int64        `json:"total"`
	Blocked    int64        `json:"blocked"`
	TopBlocked []NamedCount `json:"topBlocked"`
	TopAllowed []NamedCount `json:"topAllowed"`
	TopClients []NamedCount `json:"topClients"`
	Hourly     []HourCount  `json:"hourly"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type HourCount struct {
	Hour    int64 `json:"hour"` // unix millis of the hour start
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

func (s *Store) Stats(since time.Time) (Stats, error) {
	ms := since.UnixMilli()
	var st Stats
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM querylog WHERE ts>=?`, ms).Scan(&st.Total, &st.Blocked); err != nil {
		return st, err
	}
	top := func(q string) ([]NamedCount, error) {
		rows, err := s.db.Query(q, ms)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []NamedCount
		for rows.Next() {
			var n NamedCount
			if err := rows.Scan(&n.Name, &n.Count); err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, rows.Err()
	}
	var err error
	if st.TopBlocked, err = top(`SELECT qname, COUNT(*) c FROM querylog WHERE ts>=? AND blocked=1 GROUP BY qname ORDER BY c DESC LIMIT 10`); err != nil {
		return st, err
	}
	if st.TopAllowed, err = top(`SELECT qname, COUNT(*) c FROM querylog WHERE ts>=? AND blocked=0 GROUP BY qname ORDER BY c DESC LIMIT 10`); err != nil {
		return st, err
	}
	if st.TopClients, err = top(`SELECT CASE WHEN device_id<>'' THEN device_id ELSE client END k, COUNT(*) c FROM querylog WHERE ts>=? GROUP BY k ORDER BY c DESC LIMIT 10`); err != nil {
		return st, err
	}
	rows, err := s.db.Query(`SELECT (ts/3600000)*3600000 h, COUNT(*), COALESCE(SUM(blocked),0) FROM querylog WHERE ts>=? GROUP BY h ORDER BY h`, ms)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var h HourCount
		if err := rows.Scan(&h.Hour, &h.Total, &h.Blocked); err != nil {
			return st, err
		}
		st.Hourly = append(st.Hourly, h)
	}
	return st, rows.Err()
}

// Prune deletes query-log rows older than the retention and expired sessions.
func (s *Store) Prune(retentionDays int) {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	_, _ = s.db.Exec(`DELETE FROM querylog WHERE ts<?`, time.Now().AddDate(0, 0, -retentionDays).UnixMilli())
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
}

// ───────────────────────── helpers ─────────────────────────

// RandomToken returns n random bytes, hex-encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HashToken is how tokens are stored.
func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// NewDeviceID is a 10-char lowercase base32 id, safe in URLs and DNS labels.
func NewDeviceID() string {
	b := make([]byte, 7)
	_, _ = rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:10]
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nullable(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

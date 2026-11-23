package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ───────────────────────── migrations & helpers ─────────────────────────

func (s *Store) addColumn(table, column, def string) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	_, err = s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, def))
	return err
}

// inList appends "AND col IN (?,?,…)" (or a never-true clause for an empty list).
func inList(q, col string, vals []string, args []any) (string, []any) {
	if len(vals) == 0 {
		return q + ` AND 0`, args
	}
	q += ` AND ` + col + ` IN (` + strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",") + `)`
	for _, v := range vals {
		args = append(args, v)
	}
	return q, args
}

// ───────────────────────── JSON key/value (policies, rewrites, guard config) ─────────────────────────

// GetJSON loads a JSON value stored under key; found is false when the key is absent.
func (s *Store) GetJSON(key string, v any) (found bool, err error) {
	var raw string
	err = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

// PutJSON stores v as JSON under key.
func (s *Store) PutJSON(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}

// DeleteKey removes a key.
func (s *Store) DeleteKey(key string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE key=?`, key)
	return err
}

// JSONPrefix returns every raw value whose key starts with prefix.
func (s *Store) JSONPrefix(prefix string) (map[string][]byte, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings WHERE substr(key,1,?)=?`, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = []byte(v)
	}
	return out, rows.Err()
}

// ───────────────────────── pairing codes ─────────────────────────

// pairAlphabet has no 0/O, 1/I/L: easy to read out and type on a phone.
const pairAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// PairCode is a one-time code that links an app to its owner without a password.
type PairCode struct {
	UserID    int64
	Name      string
	Scope     string
	ExpiresAt int64
}

func normalizePairCode(code string) string {
	c := strings.NewReplacer("-", "", " ", "").Replace(strings.ToUpper(strings.TrimSpace(code)))
	if len(c) == 10 && strings.HasPrefix(c, "ZL") {
		c = c[2:]
	}
	return c
}

// CreatePairCode issues a code like ZL-ABCD-EFGH (8 random characters, ~40 bits) valid for ttl.
func (s *Store) CreatePairCode(userID int64, name, scope string, ttl time.Duration) (string, time.Time, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, 8)
	for i, v := range b {
		raw[i] = pairAlphabet[int(v)%len(pairAlphabet)]
	}
	code := "ZL-" + string(raw[:4]) + "-" + string(raw[4:])
	exp := time.Now().Add(ttl)
	if scope != "device" {
		scope = "user"
	}
	_, err := s.db.Exec(`INSERT INTO pair_codes(code_hash,user_id,name,scope,expires_at) VALUES(?,?,?,?,?)`,
		HashToken(string(raw)), userID, name, scope, exp.Unix())
	return code, exp, err
}

// ErrBadCode is returned for unknown, used or expired pairing codes.
var ErrBadCode = errors.New("that pairing code is not valid (it may have expired or been used)")

// ConsumePairCode burns a code and returns what it was issued for.
func (s *Store) ConsumePairCode(code string) (PairCode, error) {
	c := normalizePairCode(code)
	if len(c) != 8 {
		return PairCode{}, ErrBadCode
	}
	tx, err := s.db.Begin()
	if err != nil {
		return PairCode{}, err
	}
	defer tx.Rollback()
	var p PairCode
	h := HashToken(c)
	err = tx.QueryRow(`SELECT p.user_id,p.name,p.scope,p.expires_at FROM pair_codes p JOIN users u ON u.id=p.user_id
		WHERE p.code_hash=? AND u.disabled=0`, h).Scan(&p.UserID, &p.Name, &p.Scope, &p.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PairCode{}, ErrBadCode
	}
	if err != nil {
		return PairCode{}, err
	}
	if _, err := tx.Exec(`DELETE FROM pair_codes WHERE code_hash=?`, h); err != nil {
		return PairCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return PairCode{}, err
	}
	if p.ExpiresAt < time.Now().Unix() {
		return PairCode{}, ErrBadCode
	}
	return p, nil
}

// ───────────────────────── clients (auto-discovered LAN devices) ─────────────────────────

// Client is a source address seen by the DNS server.
type Client struct {
	IP        string `json:"ip"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
	Queries   int64  `json:"queries"`
	Proto     string `json:"proto"`
	Hostname  string `json:"hostname"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
}

// ClientDelta is a batch update from the in-memory tracker.
type ClientDelta struct {
	IP          string
	First, Last int64
	Queries     int64
	Proto       string
}

// UpsertClients adds query counts and timestamps.
func (s *Store) UpsertClients(ds []ClientDelta) error {
	if len(ds) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO clients(ip,first_seen,last_seen,queries,proto) VALUES(?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen), queries=queries+excluded.queries, proto=excluded.proto`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, d := range ds {
		if _, err := st.Exec(d.IP, d.First, d.Last, d.Queries, d.Proto); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Clients lists known clients, most recently seen first.
func (s *Store) Clients(limit int) ([]Client, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT ip,first_seen,last_seen,queries,proto,hostname,mac,vendor FROM clients ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.IP, &c.FirstSeen, &c.LastSeen, &c.Queries, &c.Proto, &c.Hostname, &c.MAC, &c.Vendor); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClientsToEnrich returns client IPs whose host name was last checked before `before` (unix seconds).
func (s *Store) ClientsToEnrich(before int64, limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM clients WHERE ptr_checked<? ORDER BY last_seen DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// SetClientInfo records what was learned about a client (empty values keep the old ones).
func (s *Store) SetClientInfo(ip, hostname, mac, vendor string, checked int64) error {
	_, err := s.db.Exec(`UPDATE clients SET hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END,
		mac=CASE WHEN ?<>'' THEN ? ELSE mac END, vendor=CASE WHEN ?<>'' THEN ? ELSE vendor END, ptr_checked=? WHERE ip=?`,
		hostname, hostname, mac, mac, vendor, vendor, checked, ip)
	return err
}

// ───────────────────────── Guard: decisions, alerts, bouncers ─────────────────────────

// Decision is a Guard ban (with optional expiry).
type Decision struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"` // address or CIDR
	Scenario  string `json:"scenario"`
	Reason    string `json:"reason"`
	Origin    string `json:"origin"` // auto | manual
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"` // unix seconds, 0 = never
}

// InsertDecision stores a ban and returns its id.
func (s *Store) InsertDecision(d Decision) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO guard_decisions(ip,scenario,reason,origin,created_at,expires_at) VALUES(?,?,?,?,?,?)`,
		d.IP, d.Scenario, d.Reason, d.Origin, d.CreatedAt, d.ExpiresAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RevokeDecision ends a ban early; RevokeIP ends every ban for an address.
func (s *Store) RevokeDecision(id int64) error {
	_, err := s.db.Exec(`UPDATE guard_decisions SET revoked=1 WHERE id=?`, id)
	return err
}

func (s *Store) RevokeIP(ip string) error {
	_, err := s.db.Exec(`UPDATE guard_decisions SET revoked=1 WHERE ip=? AND revoked=0`, ip)
	return err
}

// ActiveDecisions returns bans that are not revoked or expired at now (unix seconds).
func (s *Store) ActiveDecisions(now int64) ([]Decision, error) {
	rows, err := s.db.Query(`SELECT id,ip,scenario,reason,origin,created_at,expires_at FROM guard_decisions
		WHERE revoked=0 AND (expires_at=0 OR expires_at>?) ORDER BY id DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.ID, &d.IP, &d.Scenario, &d.Reason, &d.Origin, &d.CreatedAt, &d.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Alert is something Guard noticed.
type Alert struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"` // unix millis
	IP       string `json:"ip"`
	DeviceID string `json:"deviceId"`
	Scenario string `json:"scenario"`
	Message  string `json:"message"`
	Action   string `json:"action"` // alert | ban
}

func (s *Store) InsertAlerts(as []Alert) error {
	if len(as) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, a := range as {
		if _, err := tx.Exec(`INSERT INTO guard_alerts(ts,ip,device_id,scenario,message,action) VALUES(?,?,?,?,?,?)`,
			a.TS, a.IP, a.DeviceID, a.Scenario, a.Message, a.Action); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AlertFilter narrows Alerts.
type AlertFilter struct {
	SinceMs  int64
	DeviceID string
	IP       string
	Devices  []string // restrict (non-admin); nil = all
	Limit    int
}

func (s *Store) Alerts(f AlertFilter) ([]Alert, error) {
	q := `SELECT id,ts,ip,device_id,scenario,message,action FROM guard_alerts WHERE ts>=?`
	args := []any{f.SinceMs}
	if f.DeviceID != "" {
		q += ` AND device_id=?`
		args = append(args, f.DeviceID)
	}
	if f.IP != "" {
		q += ` AND ip=?`
		args = append(args, f.IP)
	}
	if f.Devices != nil {
		q, args = inList(q, "device_id", f.Devices, args)
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
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.TS, &a.IP, &a.DeviceID, &a.Scenario, &a.Message, &a.Action); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Bouncer is a firewall (OPNsense, MikroTik, the Windows app…) allowed to pull the Guard blocklist.
type Bouncer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	LastUsed  int64  `json:"lastUsed"`
	LastIP    string `json:"lastIp"`
}

// CreateBouncer returns the bouncer and its API key (shown once; only the hash is stored).
func (s *Store) CreateBouncer(name string) (Bouncer, string, error) {
	key := "zlb_" + RandomToken(24)
	b := Bouncer{ID: RandomToken(6), Name: name, CreatedAt: time.Now().Unix()}
	_, err := s.db.Exec(`INSERT INTO guard_bouncers(id,name,key_hash,created_at) VALUES(?,?,?,?)`, b.ID, b.Name, HashToken(key), b.CreatedAt)
	return b, key, err
}

func (s *Store) Bouncers() ([]Bouncer, error) {
	rows, err := s.db.Query(`SELECT id,name,created_at,last_used,last_ip FROM guard_bouncers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bouncer{}
	for rows.Next() {
		var b Bouncer
		if err := rows.Scan(&b.ID, &b.Name, &b.CreatedAt, &b.LastUsed, &b.LastIP); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) DeleteBouncer(id string) error {
	_, err := s.db.Exec(`DELETE FROM guard_bouncers WHERE id=?`, id)
	return err
}

// BouncerByKey authenticates a bouncer and records the use.
func (s *Store) BouncerByKey(key, ip string) (Bouncer, error) {
	var b Bouncer
	h := HashToken(key)
	err := s.db.QueryRow(`SELECT id,name,created_at,last_used,last_ip FROM guard_bouncers WHERE key_hash=?`, h).
		Scan(&b.ID, &b.Name, &b.CreatedAt, &b.LastUsed, &b.LastIP)
	if err != nil {
		return b, err
	}
	_, _ = s.db.Exec(`UPDATE guard_bouncers SET last_used=?, last_ip=? WHERE id=?`, time.Now().Unix(), ip, b.ID)
	return b, nil
}

// ───────────────────────── reports ─────────────────────────

// ReportFilter selects the traffic a report covers.
type ReportFilter struct {
	Since    time.Time
	Bucket   time.Duration // timeline bucket (hour or day)
	DeviceID string
	Client   string
	Devices  []string // restrict to these devices (non-admin); nil = all
}

// CountRow is a name with total and blocked counts.
type CountRow struct {
	Name    string `json:"name"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked"`
}

// Bucket is one timeline slot.
type Bucket struct {
	TS      int64 `json:"ts"` // unix millis of the slot start
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

// Report is a per-device / per-network activity summary.
type Report struct {
	Total         int64      `json:"total"`
	Blocked       int64      `json:"blocked"`
	BucketMs      int64      `json:"bucketMs"`
	Timeline      []Bucket   `json:"timeline"`
	TopServices   []CountRow `json:"topServices"`
	TopCategories []CountRow `json:"topCategories"`
	TopBlocked    []CountRow `json:"topBlocked"`
	TopAllowed    []CountRow `json:"topAllowed"`
	TopClients    []CountRow `json:"topClients"`
	TopReasons    []CountRow `json:"topReasons"`
	Alerts        []Alert    `json:"alerts"`
}

// Report builds a report. Timeline buckets are aligned to the server's local time zone for daily slots.
func (s *Store) Report(f ReportFilter) (Report, error) {
	r := Report{Timeline: []Bucket{}}
	where, args := ` ts>=?`, []any{f.Since.UnixMilli()}
	if f.DeviceID != "" {
		where += ` AND device_id=?`
		args = append(args, f.DeviceID)
	}
	if f.Client != "" {
		where += ` AND client=?`
		args = append(args, f.Client)
	}
	if f.Devices != nil {
		where, args = inList(where, "device_id", f.Devices, args)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM querylog WHERE`+where, args...).Scan(&r.Total, &r.Blocked); err != nil {
		return r, err
	}
	rowsOf := func(q string) ([]CountRow, error) {
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []CountRow{}
		for rows.Next() {
			var c CountRow
			if err := rows.Scan(&c.Name, &c.Count, &c.Blocked); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	var err error
	queries := []struct {
		dst *[]CountRow
		q   string
	}{
		{&r.TopServices, `SELECT service, COUNT(*) c, COALESCE(SUM(blocked),0) FROM querylog WHERE` + where + ` AND service<>'' GROUP BY service ORDER BY c DESC LIMIT 15`},
		{&r.TopCategories, `SELECT category, COUNT(*) c, COALESCE(SUM(blocked),0) FROM querylog WHERE` + where + ` AND category<>'' GROUP BY category ORDER BY c DESC LIMIT 15`},
		{&r.TopBlocked, `SELECT qname, COUNT(*) c, COUNT(*) FROM querylog WHERE` + where + ` AND blocked=1 GROUP BY qname ORDER BY c DESC LIMIT 15`},
		{&r.TopAllowed, `SELECT qname, COUNT(*) c, 0 FROM querylog WHERE` + where + ` AND blocked=0 GROUP BY qname ORDER BY c DESC LIMIT 15`},
		{&r.TopClients, `SELECT CASE WHEN device_id<>'' THEN device_id ELSE client END k, COUNT(*) c, COALESCE(SUM(blocked),0) FROM querylog WHERE` + where + ` GROUP BY k ORDER BY c DESC LIMIT 15`},
		{&r.TopReasons, `SELECT reason, COUNT(*) c, COUNT(*) FROM querylog WHERE` + where + ` AND blocked=1 GROUP BY reason ORDER BY c DESC LIMIT 10`},
	}
	for _, x := range queries {
		if *x.dst, err = rowsOf(x.q); err != nil {
			return r, err
		}
	}
	bucket := f.Bucket
	if bucket <= 0 {
		bucket = time.Hour
	}
	r.BucketMs = bucket.Milliseconds()
	_, offset := time.Now().Zone()
	off := int64(offset) * 1000
	if bucket < 24*time.Hour {
		off = 0
	}
	targs := append([]any{off, r.BucketMs, r.BucketMs, off}, args...)
	rows, err := s.db.Query(`SELECT ((ts+?)/?)*?-? b, COUNT(*), COALESCE(SUM(blocked),0) FROM querylog WHERE`+where+` GROUP BY b ORDER BY b`, targs...)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.TS, &b.Total, &b.Blocked); err != nil {
			return r, err
		}
		r.Timeline = append(r.Timeline, b)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	r.Alerts, err = s.Alerts(AlertFilter{SinceMs: f.Since.UnixMilli(), DeviceID: f.DeviceID, IP: f.Client, Devices: f.Devices, Limit: 50})
	return r, err
}

package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

// migrations run in order; PRAGMA user_version records how many have been applied.
// Append only — never edit a migration that has shipped.
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS cases (
		id         INTEGER PRIMARY KEY,
		created_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS targets (
		case_id INTEGER NOT NULL REFERENCES cases(id),
		value   TEXT NOT NULL,
		UNIQUE (case_id, value)
	);
	CREATE TABLE IF NOT EXISTS steps (
		id          INTEGER PRIMARY KEY,
		case_id     INTEGER NOT NULL REFERENCES cases(id),
		check_key   TEXT NOT NULL,
		target      TEXT NOT NULL,
		status      TEXT NOT NULL,
		result      TEXT,
		error       TEXT NOT NULL DEFAULT '',
		started_at  TEXT NOT NULL,
		finished_at TEXT
	);`,
	`ALTER TABLE cases ADD COLUMN title TEXT NOT NULL DEFAULT '';
	ALTER TABLE cases ADD COLUMN ticket_ref TEXT NOT NULL DEFAULT '';
	ALTER TABLE cases ADD COLUMN status TEXT NOT NULL DEFAULT 'open';
	ALTER TABLE cases ADD COLUMN last_active_at TEXT NOT NULL DEFAULT '';
	UPDATE cases SET last_active_at = created_at;
	ALTER TABLE targets ADD COLUMN kind TEXT NOT NULL DEFAULT '';
	CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
	`ALTER TABLE steps ADD COLUMN options TEXT NOT NULL DEFAULT '{}';`,
	`CREATE TABLE dismissed (
		case_id INTEGER NOT NULL REFERENCES cases(id),
		value   TEXT NOT NULL,
		UNIQUE (case_id, value)
	);`,
	`CREATE TABLE playbook_runs (
		id          INTEGER PRIMARY KEY,
		case_id     INTEGER NOT NULL REFERENCES cases(id),
		playbook    TEXT NOT NULL,
		label       TEXT NOT NULL,
		target      TEXT NOT NULL,
		boundary    TEXT NOT NULL DEFAULT '[]',
		skipped     TEXT NOT NULL DEFAULT '[]',
		total       INTEGER NOT NULL,
		status      TEXT NOT NULL,
		started_at  TEXT NOT NULL,
		finished_at TEXT
	);
	ALTER TABLE steps ADD COLUMN run_id INTEGER REFERENCES playbook_runs(id);`,
}

// Step is one execution of a Check inside a Case. Once finished it never changes.
type Step struct {
	ID         int64             `json:"id"`
	Check      string            `json:"check"`
	Target     string            `json:"target"`
	Options    map[string]string `json:"options"`          // part of the Step's identity
	Status     string            `json:"status"`           // running | ok | failed | cancelled
	RunID      int64             `json:"run_id,omitempty"` // the Playbook run that started it
	Result     json.RawMessage   `json:"result,omitempty"`
	Error      string            `json:"error,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
	// Set on a successful Step when an earlier successful Step of the same
	// Check on the same Target exists: that Step's id, and what differs.
	ComparedTo int64    `json:"compared_to,omitempty"`
	Changes    []Change `json:"changes,omitempty"`
}

type Target struct {
	Value  string   `json:"value"`
	Kind   string   `json:"kind"`
	Checks []string `json:"checks"` // keys of the Checks that apply to this kind
}

type Case struct {
	ID           int64        `json:"id"`
	Title        string       `json:"title"`
	TicketRef    string       `json:"ticket_ref"`
	Status       string       `json:"status"` // open | resolved
	CreatedAt    time.Time    `json:"created_at"`
	LastActiveAt time.Time    `json:"last_active_at"`
	Targets      []Target     `json:"targets"`
	Steps        []Step       `json:"steps,omitempty"`
	Findings     []Finding    `json:"findings,omitempty"`
	Suggestions  []Suggestion `json:"suggestions,omitempty"`
	Runs         []Run        `json:"runs,omitempty"`
}

// Run is one execution of a Playbook in a Case. Its label and Boundary notes
// are copied at the start, so later edits to the Playbook don't rewrite history.
type Run struct {
	ID         int64      `json:"id"`
	Playbook   string     `json:"playbook"`
	Label      string     `json:"label"`
	Target     string     `json:"target"`
	Boundary   []string   `json:"boundary"`
	Skipped    []skip     `json:"skipped"`
	Total      int        `json:"total"`  // entries in the Playbook
	Status     string     `json:"status"` // running | done | cancelled
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type store struct{ db *sql.DB }

// querier is *sql.DB or *sql.Tx, so reads can share one transaction.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func openStore(dir string) (*store, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "stackwell.db")+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		// PRAGMA can't take a bound parameter; i is ours, not input.
		if _, err := tx.Exec(`PRAGMA user_version = ` + strconv.Itoa(i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// createCase creates a Case with one Target and makes it the active Case.
func (s *store) createCase(value, kind string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	t := now()
	res, err := tx.Exec(`INSERT INTO cases (created_at, last_active_at) VALUES (?, ?)`, t, t)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if _, err := tx.Exec(`INSERT INTO targets (case_id, value, kind) VALUES (?, ?, ?)`, id, value, kind); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES ('active_case', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, id); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// addTarget adds a Target to a Case; added is false if it was already there.
func (s *store) addTarget(caseID int64, value, kind string) (added bool, err error) {
	res, err := s.db.Exec(`INSERT INTO targets (case_id, value, kind) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, caseID, value, kind)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *store) caseExists(id int64) bool {
	var one int
	return s.db.QueryRow(`SELECT 1 FROM cases WHERE id = ?`, id).Scan(&one) == nil
}

type caseEdit struct {
	Title     *string `json:"title"`
	TicketRef *string `json:"ticket_ref"`
	Status    *string `json:"status"`
}

func (s *store) editCase(id int64, e caseEdit) error {
	_, err := s.db.Exec(`UPDATE cases SET
		title = coalesce(?, title), ticket_ref = coalesce(?, ticket_ref), status = coalesce(?, status)
		WHERE id = ?`, e.Title, e.TicketRef, e.Status, id)
	return err
}

// setActive makes a Case the active one, or clears it with id 0.
func (s *store) setActive(id int64) error {
	if id == 0 {
		_, err := s.db.Exec(`DELETE FROM settings WHERE key = 'active_case'`)
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE cases SET last_active_at = ? WHERE id = ?`, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES ('active_case', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// activeCase returns the active Case's id, or 0 if none.
func (s *store) activeCase() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'active_case'`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// optionsKey is the canonical form of a Step's options (JSON sorts map keys).
func optionsKey(opts map[string]string) string {
	if opts == nil {
		opts = map[string]string{}
	}
	b, _ := json.Marshal(opts)
	return string(b)
}

func (s *store) startStep(caseID int64, check, target string, opts map[string]string, runID int64) (Step, error) {
	st := Step{Check: check, Target: target, Options: opts, RunID: runID, Status: "running", StartedAt: time.Now().UTC()}
	res, err := s.db.Exec(`INSERT INTO steps (case_id, check_key, target, options, run_id, status, started_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		caseID, check, target, optionsKey(opts), nullID(runID), st.Status, st.StartedAt.Format(time.RFC3339Nano))
	if err != nil {
		return st, err
	}
	st.ID, _ = res.LastInsertId()
	return st, nil
}

// finishStep records a Step's outcome; cancelled means the rep (or shutdown)
// stopped it, which is neither a result nor a failure.
func (s *store) finishStep(st *Step, result any, runErr error, cancelled bool) error {
	t := time.Now().UTC()
	st.FinishedAt = &t
	st.Status = "ok"
	switch {
	case cancelled:
		st.Status, st.Error = "cancelled", ""
	case runErr != nil:
		st.Status, st.Error = "failed", runErr.Error()
	default:
		st.Result, _ = json.Marshal(result)
	}
	_, err := s.db.Exec(`UPDATE steps SET status = ?, result = ?, error = ?, finished_at = ? WHERE id = ?`,
		st.Status, nullable(st.Result), st.Error, t.Format(time.RFC3339Nano), st.ID)
	return err
}

const caseColumns = `id, title, ticket_ref, status, created_at, last_active_at`

func scanCase(row interface{ Scan(...any) error }) (Case, error) {
	var c Case
	var created, active string
	if err := row.Scan(&c.ID, &c.Title, &c.TicketRef, &c.Status, &created, &active); err != nil {
		return c, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	c.LastActiveAt, _ = time.Parse(time.RFC3339Nano, active)
	return c, nil
}

func (s *store) targets(caseID int64) ([]Target, error) { return readTargets(s.db, caseID) }

func readTargets(q querier, caseID int64) ([]Target, error) {
	rows, err := q.Query(`SELECT value, kind FROM targets WHERE case_id = ? ORDER BY rowid`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ts := []Target{}
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.Value, &t.Kind); err != nil {
			return nil, err
		}
		t.Checks = checksFor(t.Kind)
		ts = append(ts, t)
	}
	return ts, rows.Err()
}

// recentCases lists Cases, most recently active first, without their Steps.
func (s *store) recentCases(limit int) ([]Case, error) {
	rows, err := s.db.Query(`SELECT `+caseColumns+` FROM cases ORDER BY last_active_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	var cs []Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		cs = append(cs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range cs {
		if cs[i].Targets, err = s.targets(cs[i].ID); err != nil {
			return nil, err
		}
	}
	return cs, nil
}

// getCase returns sql.ErrNoRows when the Case doesn't exist. It reads in one
// transaction, so a Case is a single consistent snapshot: never a run that
// has finished next to a Step it still shows as running.
func (s *store) getCase(id int64) (Case, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Case{}, err
	}
	defer tx.Rollback()
	c, err := scanCase(tx.QueryRow(`SELECT `+caseColumns+` FROM cases WHERE id = ?`, id))
	if err != nil {
		return c, err
	}
	if c.Targets, err = readTargets(tx, id); err != nil {
		return c, err
	}
	if c.Steps, err = readSteps(tx, id); err != nil {
		return c, err
	}
	compareSteps(c.Steps)
	c.Findings = caseFindings(c.Steps, c.Targets)
	dismissed, err := readDismissed(tx, id)
	if err != nil {
		return c, err
	}
	c.Suggestions = caseSuggestions(c.Steps, c.Targets, dismissed)
	c.Runs, err = readRuns(tx, id)
	return c, err
}

func readSteps(q querier, caseID int64) ([]Step, error) {
	rows, err := q.Query(`SELECT id, check_key, target, options, coalesce(run_id, 0), status, result, error, started_at, finished_at FROM steps WHERE case_id = ? ORDER BY id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	steps := []Step{}
	for rows.Next() {
		var st Step
		var result, finished sql.NullString
		var started, opts string
		if err := rows.Scan(&st.ID, &st.Check, &st.Target, &opts, &st.RunID, &st.Status, &result, &st.Error, &started, &finished); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(opts), &st.Options)
		if result.Valid {
			st.Result = json.RawMessage(result.String)
		}
		st.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if finished.Valid {
			t, _ := time.Parse(time.RFC3339Nano, finished.String)
			st.FinishedAt = &t
		}
		steps = append(steps, st)
	}
	return steps, rows.Err()
}

// stepIdentity is what makes two Steps runs of "the same thing".
func stepIdentity(st Step) [3]string { return [3]string{st.Check, st.Target, optionsKey(st.Options)} }

// compareSteps fills ComparedTo and Changes on each successful Step (in id
// order) against the latest earlier successful Step of the same identity.
func compareSteps(steps []Step) {
	last := map[[3]string]*Step{}
	for i := range steps {
		st := &steps[i]
		if st.Status != "ok" {
			continue
		}
		key := stepIdentity(*st)
		if prev := last[key]; prev != nil {
			st.ComparedTo, st.Changes = prev.ID, diffResults(prev.Result, st.Result)
		}
		last[key] = st
	}
}

// previousOK returns the latest successful Step with the same Check, Target
// and options in a Case before the given Step id, or ok=false.
func (s *store) previousOK(caseID int64, check, target string, opts map[string]string, before int64) (Step, bool) {
	var st Step
	var result string
	err := s.db.QueryRow(`SELECT id, result FROM steps WHERE case_id = ? AND check_key = ? AND target = ? AND options = ? AND status = 'ok' AND id < ?
		ORDER BY id DESC LIMIT 1`, caseID, check, target, optionsKey(opts), before).Scan(&st.ID, &result)
	st.Result = json.RawMessage(result)
	return st, err == nil
}

// classifyTargets fills in the kind of Targets saved before kinds existed.
func (s *store) classifyTargets() error {
	rows, err := s.db.Query(`SELECT rowid, value FROM targets WHERE kind = ''`)
	if err != nil {
		return err
	}
	type row struct {
		id    int64
		value string
	}
	var todo []row
	for rows.Next() {
		var r row
		rows.Scan(&r.id, &r.value)
		todo = append(todo, r)
	}
	rows.Close()
	for _, r := range todo {
		if _, kind, err := parseTarget(r.value); err == nil {
			if _, err := s.db.Exec(`UPDATE targets SET kind = ? WHERE rowid = ?`, kind, r.id); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (s *store) dismiss(caseID int64, value string) error {
	_, err := s.db.Exec(`INSERT INTO dismissed (case_id, value) VALUES (?, ?) ON CONFLICT DO NOTHING`, caseID, value)
	return err
}

func readDismissed(q querier, caseID int64) ([]string, error) {
	rows, err := q.Query(`SELECT value FROM dismissed WHERE case_id = ?`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *store) createRun(caseID int64, p *Playbook, target string) (int64, error) {
	boundary, _ := json.Marshal(p.Boundary)
	res, err := s.db.Exec(`INSERT INTO playbook_runs (case_id, playbook, label, target, boundary, total, status, started_at) VALUES (?, ?, ?, ?, ?, ?, 'running', ?)`,
		caseID, p.Name, p.Label, target, string(boundary), len(p.Entries), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *store) finishRun(runID int64, status string, skipped []skip) error {
	b, _ := json.Marshal(skipped)
	_, err := s.db.Exec(`UPDATE playbook_runs SET status = ?, skipped = ?, finished_at = ? WHERE id = ?`, status, string(b), now(), runID)
	return err
}

// runCase returns the Case a run belongs to, or sql.ErrNoRows.
func (s *store) runCase(runID int64) (int64, error) {
	var caseID int64
	err := s.db.QueryRow(`SELECT case_id FROM playbook_runs WHERE id = ?`, runID).Scan(&caseID)
	return caseID, err
}

func (s *store) runs(caseID int64) ([]Run, error) { return readRuns(s.db, caseID) }

func readRuns(q querier, caseID int64) ([]Run, error) {
	rows, err := q.Query(`SELECT id, playbook, label, target, boundary, skipped, total, status, started_at, finished_at FROM playbook_runs WHERE case_id = ? ORDER BY id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		var boundary, skipped, started string
		var finished sql.NullString
		if err := rows.Scan(&r.ID, &r.Playbook, &r.Label, &r.Target, &boundary, &skipped, &r.Total, &r.Status, &started, &finished); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(boundary), &r.Boundary)
		json.Unmarshal([]byte(skipped), &r.Skipped)
		r.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if finished.Valid {
			t, _ := time.Parse(time.RFC3339Nano, finished.String)
			r.FinishedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// failRunning marks Steps left "running" by a previous process as failed;
// nothing will ever finish them.
func (s *store) failRunning() error {
	if _, err := s.db.Exec(`UPDATE steps SET status = 'failed', error = 'interrupted: Stackwell stopped while this Step was running', finished_at = ? WHERE status = 'running'`, now()); err != nil {
		return err
	}
	// A run's scheduler lived in memory; nothing will resume it.
	_, err := s.db.Exec(`UPDATE playbook_runs SET status = 'cancelled', finished_at = ? WHERE status = 'running'`, now())
	return err
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func nullable(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

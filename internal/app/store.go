package app

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS cases (
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
);`

// Step is one execution of a Check inside a Case. Once finished it never changes.
type Step struct {
	ID         int64           `json:"id"`
	Check      string          `json:"check"`
	Target     string          `json:"target"`
	Status     string          `json:"status"` // running | ok | failed
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

type Case struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Targets   []string  `json:"targets"`
	Steps     []Step    `json:"steps"`
}

type store struct{ db *sql.DB }

func openStore(dir string) (*store, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "stackwell.db")+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db}, nil
}

func (s *store) createCase(target string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO cases (created_at) VALUES (?)`, now())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if _, err := tx.Exec(`INSERT INTO targets (case_id, value) VALUES (?, ?)`, id, target); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (s *store) startStep(caseID int64, check, target string) (Step, error) {
	st := Step{Check: check, Target: target, Status: "running", StartedAt: time.Now().UTC()}
	res, err := s.db.Exec(`INSERT INTO steps (case_id, check_key, target, status, started_at) VALUES (?, ?, ?, ?, ?)`,
		caseID, check, target, st.Status, st.StartedAt.Format(time.RFC3339Nano))
	if err != nil {
		return st, err
	}
	st.ID, _ = res.LastInsertId()
	return st, nil
}

func (s *store) finishStep(st *Step, result any, runErr error) error {
	t := time.Now().UTC()
	st.FinishedAt = &t
	st.Status = "ok"
	if runErr != nil {
		st.Status, st.Error = "failed", runErr.Error()
	} else {
		st.Result, _ = json.Marshal(result)
	}
	_, err := s.db.Exec(`UPDATE steps SET status = ?, result = ?, error = ?, finished_at = ? WHERE id = ?`,
		st.Status, nullable(st.Result), st.Error, t.Format(time.RFC3339Nano), st.ID)
	return err
}

// getCase returns sql.ErrNoRows when the Case doesn't exist.
func (s *store) getCase(id int64) (Case, error) {
	c := Case{ID: id, Targets: []string{}, Steps: []Step{}}
	var created string
	if err := s.db.QueryRow(`SELECT created_at FROM cases WHERE id = ?`, id).Scan(&created); err != nil {
		return c, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)

	rows, err := s.db.Query(`SELECT value FROM targets WHERE case_id = ? ORDER BY rowid`, id)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		c.Targets = append(c.Targets, v)
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT id, check_key, target, status, result, error, started_at, finished_at FROM steps WHERE case_id = ? ORDER BY id`, id)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var st Step
		var result, finished sql.NullString
		var started string
		if err := rows.Scan(&st.ID, &st.Check, &st.Target, &st.Status, &result, &st.Error, &started, &finished); err != nil {
			return c, err
		}
		if result.Valid {
			st.Result = json.RawMessage(result.String)
		}
		st.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if finished.Valid {
			t, _ := time.Parse(time.RFC3339Nano, finished.String)
			st.FinishedAt = &t
		}
		c.Steps = append(c.Steps, st)
	}
	return c, rows.Err()
}

// failRunning marks Steps left "running" by a previous process as failed;
// nothing will ever finish them.
func (s *store) failRunning() error {
	_, err := s.db.Exec(`UPDATE steps SET status = 'failed', error = 'interrupted: Stackwell stopped while this Step was running', finished_at = ? WHERE status = 'running'`, now())
	return err
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func nullable(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

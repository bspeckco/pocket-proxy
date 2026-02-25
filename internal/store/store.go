package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrRunNotActive    = errors.New("run is not active")
	ErrRunExpired      = errors.New("run has expired")
	ErrBudgetExhausted = errors.New("budget exhausted")
)

type Store struct {
	db     *sql.DB
	mu     sync.Mutex
	idSize int
	maxRespSize int
}

type Run struct {
	ID           string
	Token        string
	Service      string
	RequestsUsed int
	Status       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type RequestEntry struct {
	ID              string
	RunID           string
	Method          string
	Path            string
	StatusCode      int
	Counted         bool
	ResponseBody    []byte
	ContentType     string
	DedupKey        string
	CreatedAt       time.Time
}

type StoreOptions struct {
	IDSize      int
	MaxRespSize int
}

func New(opts ...StoreOptions) (*Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// Single connection for in-memory DB consistency
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE runs (
			id TEXT PRIMARY KEY,
			token TEXT UNIQUE NOT NULL,
			service TEXT NOT NULL,
			requests_used INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX idx_runs_token ON runs(token);

		CREATE TABLE request_log (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			counted INTEGER NOT NULL DEFAULT 0,
			response_body BLOB,
			content_type TEXT NOT NULL DEFAULT '',
			dedup_key TEXT,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (run_id) REFERENCES runs(id)
		);
		CREATE INDEX idx_request_log_run_id ON request_log(run_id);
		CREATE INDEX idx_request_log_dedup ON request_log(run_id, dedup_key);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating tables: %w", err)
	}

	s := &Store{db: db, idSize: 16, maxRespSize: 1 << 20}
	if len(opts) > 0 {
		if opts[0].IDSize > 0 {
			s.idSize = opts[0].IDSize
		}
		if opts[0].MaxRespSize > 0 {
			s.maxRespSize = opts[0].MaxRespSize
		}
	}

	return s, nil
}

func (s *Store) IDSize() int      { return s.idSize }
func (s *Store) MaxRespSize() int { return s.maxRespSize }

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) CreateRun(service string, expiresAt time.Time) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := GenerateID(s.idSize)
	token := GenerateID(s.idSize)
	now := time.Now().UTC()

	_, err := s.db.Exec(
		`INSERT INTO runs (id, token, service, requests_used, status, created_at, expires_at)
		 VALUES (?, ?, ?, 0, 'active', ?, ?)`,
		id, token, service, now.Unix(), expiresAt.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating run: %w", err)
	}

	return &Run{
		ID:           id,
		Token:        token,
		Service:      service,
		RequestsUsed: 0,
		Status:       "active",
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Store) GetRun(id string) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getRunLocked(id)
}

func (s *Store) getRunLocked(id string) (*Run, error) {
	var r Run
	var createdAt, expiresAt int64
	err := s.db.QueryRow(
		`SELECT id, token, service, requests_used, status, created_at, expires_at
		 FROM runs WHERE id = ?`, id,
	).Scan(&r.ID, &r.Token, &r.Service, &r.RequestsUsed, &r.Status, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting run: %w", err)
	}
	r.CreatedAt = time.Unix(createdAt, 0).UTC()
	r.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return &r, nil
}

func (s *Store) GetRunByToken(token string) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var r Run
	var createdAt, expiresAt int64
	err := s.db.QueryRow(
		`SELECT id, token, service, requests_used, status, created_at, expires_at
		 FROM runs WHERE token = ?`, token,
	).Scan(&r.ID, &r.Token, &r.Service, &r.RequestsUsed, &r.Status, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting run by token: %w", err)
	}
	r.CreatedAt = time.Unix(createdAt, 0).UTC()
	r.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return &r, nil
}

// ReserveRequest atomically checks run status, expiration, and budget, then
// increments requests_used. Returns the new count. If the upstream response
// turns out to be non-2xx, call ReleaseRequest to undo the increment.
func (s *Store) ReserveRequest(runID string, maxRequests int) (newCount int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Unix()

	result, err := s.db.Exec(
		`UPDATE runs SET requests_used = requests_used + 1
		 WHERE id = ? AND status = 'active' AND requests_used < ? AND expires_at > ?`,
		runID, maxRequests, now,
	)
	if err != nil {
		return 0, fmt.Errorf("reserving request: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Determine why the reservation failed
		r, err := s.getRunLocked(runID)
		if err != nil {
			return 0, err
		}
		if r == nil {
			return 0, fmt.Errorf("run not found: %s", runID)
		}
		if r.Status == "exhausted" {
			return r.RequestsUsed, ErrBudgetExhausted
		}
		if r.Status != "active" {
			return r.RequestsUsed, ErrRunNotActive
		}
		if time.Now().UTC().After(r.ExpiresAt) {
			// Persist expired status
			s.db.Exec(`UPDATE runs SET status = 'expired' WHERE id = ? AND status = 'active'`, runID)
			return r.RequestsUsed, ErrRunExpired
		}
		if r.RequestsUsed >= maxRequests {
			// Persist exhausted status
			s.db.Exec(`UPDATE runs SET status = 'exhausted' WHERE id = ? AND status = 'active'`, runID)
			return r.RequestsUsed, ErrBudgetExhausted
		}
		return 0, fmt.Errorf("unexpected: could not reserve request for run %s", runID)
	}

	var count int
	err = s.db.QueryRow(`SELECT requests_used FROM runs WHERE id = ?`, runID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("reading updated count: %w", err)
	}

	// If this reservation hit the max, persist exhausted status
	if count >= maxRequests {
		s.db.Exec(`UPDATE runs SET status = 'exhausted' WHERE id = ? AND status = 'active'`, runID)
	}

	return count, nil
}

// ReleaseRequest decrements requests_used for a run. Called when the upstream
// response is non-2xx and shouldn't count against budget.
func (s *Store) ReleaseRequest(runID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If status was set to exhausted, revert to active since we're releasing
	s.db.Exec(`UPDATE runs SET status = 'active' WHERE id = ? AND status = 'exhausted'`, runID)

	_, err := s.db.Exec(
		`UPDATE runs SET requests_used = requests_used - 1 WHERE id = ? AND requests_used > 0`,
		runID,
	)
	return err
}

func (s *Store) UpdateRunStatus(runID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`UPDATE runs SET status = ? WHERE id = ?`, status, runID)
	if err != nil {
		return fmt.Errorf("updating run status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("run not found: %s", runID)
	}
	return nil
}

func (s *Store) LogRequest(entry *RequestEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.ID == "" {
		entry.ID = GenerateID(s.idSize)
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	_, err := s.db.Exec(
		`INSERT INTO request_log (id, run_id, method, path, status_code, counted, response_body, content_type, dedup_key, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.RunID, entry.Method, entry.Path, entry.StatusCode,
		boolToInt(entry.Counted), entry.ResponseBody, entry.ContentType, entry.DedupKey, entry.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("logging request: %w", err)
	}
	return nil
}

func (s *Store) GetRequestLogs(runID string) ([]RequestEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(
		`SELECT id, run_id, method, path, status_code, counted, response_body, content_type, dedup_key, created_at
		 FROM request_log WHERE run_id = ? ORDER BY created_at ASC`, runID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying request logs: %w", err)
	}
	defer rows.Close()

	var entries []RequestEntry
	for rows.Next() {
		var e RequestEntry
		var counted int
		var createdAt int64
		if err := rows.Scan(&e.ID, &e.RunID, &e.Method, &e.Path, &e.StatusCode,
			&counted, &e.ResponseBody, &e.ContentType, &e.DedupKey, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning request log: %w", err)
		}
		e.Counted = counted != 0
		e.CreatedAt = time.Unix(createdAt, 0).UTC()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) GetResponses(runID string) ([]RequestEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(
		`SELECT id, run_id, method, path, status_code, counted, response_body, content_type, dedup_key, created_at
		 FROM request_log WHERE run_id = ? AND response_body IS NOT NULL ORDER BY created_at ASC`, runID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying responses: %w", err)
	}
	defer rows.Close()

	var entries []RequestEntry
	for rows.Next() {
		var e RequestEntry
		var counted int
		var createdAt int64
		if err := rows.Scan(&e.ID, &e.RunID, &e.Method, &e.Path, &e.StatusCode,
			&counted, &e.ResponseBody, &e.ContentType, &e.DedupKey, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning response: %w", err)
		}
		e.Counted = counted != 0
		e.CreatedAt = time.Unix(createdAt, 0).UTC()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) FindDedupEntry(runID, dedupKey string) (*RequestEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var e RequestEntry
	var counted int
	var createdAt int64
	err := s.db.QueryRow(
		`SELECT id, run_id, method, path, status_code, counted, response_body, content_type, dedup_key, created_at
		 FROM request_log WHERE run_id = ? AND dedup_key = ? AND counted = 1
		 ORDER BY created_at DESC LIMIT 1`, runID, dedupKey,
	).Scan(&e.ID, &e.RunID, &e.Method, &e.Path, &e.StatusCode,
		&counted, &e.ResponseBody, &e.ContentType, &e.DedupKey, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("finding dedup entry: %w", err)
	}
	e.Counted = counted != 0
	e.CreatedAt = time.Unix(createdAt, 0).UTC()
	return &e, nil
}

func (s *Store) DeleteRunData(runID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM request_log WHERE run_id = ?`, runID); err != nil {
		return fmt.Errorf("deleting request logs: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM runs WHERE id = ?`, runID); err != nil {
		return fmt.Errorf("deleting run: %w", err)
	}

	return tx.Commit()
}

// GenerateID creates a random alphanumeric string using rejection sampling
// to avoid modulo bias.
func GenerateID(size int) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	const alen = len(alphabet) // 62
	// Largest multiple of 62 that fits in a byte: 62*4 = 248
	const maxValid byte = byte((256 / alen) * alen) // 248

	result := make([]byte, size)
	buf := make([]byte, size+size/2) // extra to reduce retry loops
	idx := 0
	for idx < size {
		if _, err := rand.Read(buf); err != nil {
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		for _, b := range buf {
			if b < maxValid {
				result[idx] = alphabet[b%byte(alen)]
				idx++
				if idx >= size {
					break
				}
			}
		}
	}
	return string(result)
}

// DedupKey computes a dedup hash from method, path, and optional request body.
func DedupKey(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte("|"))
	h.Write([]byte(path))
	if len(body) > 0 {
		h.Write([]byte("|"))
		h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

package store

import (
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndGetRun(t *testing.T) {
	s := newTestStore(t)

	expires := time.Now().Add(time.Hour).UTC()
	run, err := s.CreateRun("test-svc", expires)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if run.ID == "" {
		t.Error("expected non-empty ID")
	}
	if run.Token == "" {
		t.Error("expected non-empty token")
	}
	if run.Service != "test-svc" {
		t.Errorf("expected service 'test-svc', got %q", run.Service)
	}
	if run.RequestsUsed != 0 {
		t.Errorf("expected 0 requests_used, got %d", run.RequestsUsed)
	}
	if run.Status != "active" {
		t.Errorf("expected status 'active', got %q", run.Status)
	}

	// Get by ID
	got, err := s.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got == nil {
		t.Fatal("expected run, got nil")
	}
	if got.ID != run.ID {
		t.Errorf("expected ID %q, got %q", run.ID, got.ID)
	}
	if got.Token != run.Token {
		t.Errorf("expected token %q, got %q", run.Token, got.Token)
	}
}

func TestGetRunByToken(t *testing.T) {
	s := newTestStore(t)

	run, err := s.CreateRun("svc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRunByToken(run.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected run, got nil")
	}
	if got.ID != run.ID {
		t.Errorf("expected ID %q, got %q", run.ID, got.ID)
	}
}

func TestGetRunNotFound(t *testing.T) {
	s := newTestStore(t)

	got, err := s.GetRun("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestGetRunByTokenNotFound(t *testing.T) {
	s := newTestStore(t)

	got, err := s.GetRunByToken("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestReserveAndRelease(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	// Reserve first request
	count, err := s.ReserveRequest(run.ID, 5)
	if err != nil {
		t.Fatalf("ReserveRequest: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// Reserve second request
	count, err = s.ReserveRequest(run.ID, 5)
	if err != nil {
		t.Fatalf("ReserveRequest: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	// Release one (simulating non-2xx response)
	if err := s.ReleaseRequest(run.ID); err != nil {
		t.Fatalf("ReleaseRequest: %v", err)
	}

	// Verify count is back to 1
	got, _ := s.GetRun(run.ID)
	if got.RequestsUsed != 1 {
		t.Errorf("expected 1 after release, got %d", got.RequestsUsed)
	}
}

func TestReserveBudgetExhausted(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	// Use all budget
	for i := 0; i < 3; i++ {
		_, err := s.ReserveRequest(run.ID, 3)
		if err != nil {
			t.Fatalf("ReserveRequest %d: %v", i, err)
		}
	}

	// Next should fail with budget exhausted
	_, err := s.ReserveRequest(run.ID, 3)
	if err != ErrBudgetExhausted {
		t.Errorf("expected ErrBudgetExhausted, got %v", err)
	}

	// Status should now be 'exhausted'
	got, _ := s.GetRun(run.ID)
	if got.Status != "exhausted" {
		t.Errorf("expected status 'exhausted', got %q", got.Status)
	}
}

func TestReserveExhaustedThenRelease(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	// Exhaust budget
	for i := 0; i < 3; i++ {
		s.ReserveRequest(run.ID, 3)
	}

	// Release one (simulating non-2xx that exhausted the budget)
	s.ReleaseRequest(run.ID)

	// Status should revert to 'active'
	got, _ := s.GetRun(run.ID)
	if got.Status != "active" {
		t.Errorf("expected status 'active' after release, got %q", got.Status)
	}
	if got.RequestsUsed != 2 {
		t.Errorf("expected 2 requests_used after release, got %d", got.RequestsUsed)
	}
}

func TestReserveExpiredRun(t *testing.T) {
	s := newTestStore(t)

	// Create run that's already expired
	run, _ := s.CreateRun("svc", time.Now().Add(-time.Second))

	_, err := s.ReserveRequest(run.ID, 5)
	if err != ErrRunExpired {
		t.Errorf("expected ErrRunExpired, got %v", err)
	}

	// Status should now be 'expired'
	got, _ := s.GetRun(run.ID)
	if got.Status != "expired" {
		t.Errorf("expected status 'expired', got %q", got.Status)
	}
}

func TestReserveRevokedRun(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))
	s.UpdateRunStatus(run.ID, "revoked")

	_, err := s.ReserveRequest(run.ID, 5)
	if err != ErrRunNotActive {
		t.Errorf("expected ErrRunNotActive, got %v", err)
	}
}

func TestUpdateRunStatus(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	if err := s.UpdateRunStatus(run.ID, "revoked"); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetRun(run.ID)
	if got.Status != "revoked" {
		t.Errorf("expected 'revoked', got %q", got.Status)
	}
}

func TestUpdateRunStatusNotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.UpdateRunStatus("nonexistent", "revoked")
	if err == nil {
		t.Error("expected error for nonexistent run")
	}
}

func TestLogAndGetRequests(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	entry := &RequestEntry{
		RunID:      run.ID,
		Method:     "GET",
		Path:       "/test?q=hello",
		StatusCode: 200,
		Counted:    true,
		DedupKey:   "abc123",
	}
	if err := s.LogRequest(entry); err != nil {
		t.Fatal(err)
	}
	if entry.ID == "" {
		t.Error("expected ID to be set")
	}

	logs, err := s.GetRequestLogs(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].Method != "GET" {
		t.Errorf("expected method GET, got %q", logs[0].Method)
	}
	if logs[0].Path != "/test?q=hello" {
		t.Errorf("expected path '/test?q=hello', got %q", logs[0].Path)
	}
	if !logs[0].Counted {
		t.Error("expected counted=true")
	}
}

func TestLogRequestWithResponseBody(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	body := []byte(`{"data":"hello"}`)
	entry := &RequestEntry{
		RunID:        run.ID,
		Method:       "GET",
		Path:         "/test",
		StatusCode:   200,
		Counted:      true,
		ResponseBody: body,
		ContentType:  "application/json",
		DedupKey:     DedupKey("GET", "/test", nil),
	}
	if err := s.LogRequest(entry); err != nil {
		t.Fatal(err)
	}

	responses, err := s.GetResponses(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if string(responses[0].ResponseBody) != `{"data":"hello"}` {
		t.Errorf("unexpected response body: %s", responses[0].ResponseBody)
	}
	if responses[0].ContentType != "application/json" {
		t.Errorf("unexpected content type: %s", responses[0].ContentType)
	}
}

func TestGetResponsesEmpty(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	// Log request without body
	s.LogRequest(&RequestEntry{
		RunID:      run.ID,
		Method:     "GET",
		Path:       "/test",
		StatusCode: 200,
		Counted:    true,
	})

	responses, err := s.GetResponses(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 0 {
		t.Errorf("expected 0 responses, got %d", len(responses))
	}
}

func TestFindDedupEntry(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	dk := DedupKey("GET", "/test?q=hello", nil)
	entry := &RequestEntry{
		RunID:        run.ID,
		Method:       "GET",
		Path:         "/test?q=hello",
		StatusCode:   200,
		Counted:      true,
		ResponseBody: []byte(`{"result":"data"}`),
		ContentType:  "application/json",
		DedupKey:     dk,
	}
	s.LogRequest(entry)

	found, err := s.FindDedupEntry(run.ID, dk)
	if err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatal("expected dedup entry, got nil")
	}
	if string(found.ResponseBody) != `{"result":"data"}` {
		t.Errorf("unexpected response body: %s", found.ResponseBody)
	}
	if found.ContentType != "application/json" {
		t.Errorf("unexpected content type: %s", found.ContentType)
	}
}

func TestFindDedupEntryNotFound(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	found, err := s.FindDedupEntry(run.ID, "nonexistent-key")
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Errorf("expected nil, got %+v", found)
	}
}

func TestFindDedupOnlyCountedEntries(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	dk := DedupKey("GET", "/test", nil)
	// Log uncounted entry (non-2xx response)
	s.LogRequest(&RequestEntry{
		RunID:      run.ID,
		Method:     "GET",
		Path:       "/test",
		StatusCode: 500,
		Counted:    false,
		DedupKey:   dk,
	})

	found, err := s.FindDedupEntry(run.ID, dk)
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Error("expected nil for uncounted entry")
	}
}

func TestDeleteRunData(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	s.LogRequest(&RequestEntry{
		RunID:      run.ID,
		Method:     "GET",
		Path:       "/test",
		StatusCode: 200,
		Counted:    true,
	})

	if err := s.DeleteRunData(run.ID); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetRun(run.ID)
	if got != nil {
		t.Error("expected run to be deleted")
	}

	logs, _ := s.GetRequestLogs(run.ID)
	if len(logs) != 0 {
		t.Errorf("expected 0 logs after delete, got %d", len(logs))
	}
}

func TestDedupKey(t *testing.T) {
	k1 := DedupKey("GET", "/test?q=hello", nil)
	k2 := DedupKey("GET", "/test?q=hello", nil)
	k3 := DedupKey("POST", "/test?q=hello", nil)
	k4 := DedupKey("GET", "/test?q=world", nil)

	if k1 != k2 {
		t.Error("same inputs should produce same key")
	}
	if k1 == k3 {
		t.Error("different methods should produce different keys")
	}
	if k1 == k4 {
		t.Error("different paths should produce different keys")
	}
}

func TestDedupKeyWithBody(t *testing.T) {
	k1 := DedupKey("POST", "/test", []byte(`{"a":1}`))
	k2 := DedupKey("POST", "/test", []byte(`{"a":1}`))
	k3 := DedupKey("POST", "/test", []byte(`{"a":2}`))
	k4 := DedupKey("POST", "/test", nil)

	if k1 != k2 {
		t.Error("same body should produce same key")
	}
	if k1 == k3 {
		t.Error("different bodies should produce different keys")
	}
	if k1 == k4 {
		t.Error("body vs no-body should produce different keys")
	}
}

func TestGenerateID(t *testing.T) {
	id := GenerateID(16)
	if len(id) != 16 {
		t.Errorf("expected length 16, got %d", len(id))
	}

	// Check all characters are in the alphabet
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for _, c := range id {
		found := false
		for _, a := range alphabet {
			if c == a {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("character %q not in alphabet", c)
		}
	}

	// Check uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateID(16)
		if ids[id] {
			t.Errorf("duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

func TestGenerateIDDistribution(t *testing.T) {
	// Verify rejection sampling produces approximately uniform distribution
	counts := make(map[byte]int)
	for i := 0; i < 10000; i++ {
		id := GenerateID(1)
		counts[id[0]]++
	}
	// With 62 chars and 10000 samples, expected ~161 per char
	// Allow wide range to avoid flaky tests but catch severe bias
	for c, n := range counts {
		if n < 80 || n > 280 {
			t.Errorf("character %q appeared %d times (expected ~161)", c, n)
		}
	}
}

func TestStoreOptionsConfigurable(t *testing.T) {
	s, err := New(StoreOptions{IDSize: 32, MaxRespSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if s.IDSize() != 32 {
		t.Errorf("expected IDSize 32, got %d", s.IDSize())
	}
	if s.MaxRespSize() != 512 {
		t.Errorf("expected MaxRespSize 512, got %d", s.MaxRespSize())
	}

	// Verify IDs are actually generated at the configured size
	run, err := s.CreateRun("svc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(run.ID) != 32 {
		t.Errorf("expected run ID length 32, got %d", len(run.ID))
	}
}

func TestConcurrentReserve(t *testing.T) {
	s := newTestStore(t)

	run, _ := s.CreateRun("svc", time.Now().Add(time.Hour))

	maxReqs := 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	exhaustedCount := 0

	// Launch 20 goroutines trying to reserve, with max budget of 10
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ReserveRequest(run.ID, maxReqs)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
			} else if err == ErrBudgetExhausted {
				exhaustedCount++
			}
		}()
	}

	wg.Wait()

	if successCount != maxReqs {
		t.Errorf("expected exactly %d successful reserves, got %d", maxReqs, successCount)
	}
	if exhaustedCount != 10 {
		t.Errorf("expected 10 exhausted, got %d", exhaustedCount)
	}

	got, _ := s.GetRun(run.ID)
	if got.RequestsUsed != maxReqs {
		t.Errorf("expected %d requests_used, got %d", maxReqs, got.RequestsUsed)
	}
}

func TestMultipleRunsIsolation(t *testing.T) {
	s := newTestStore(t)

	run1, _ := s.CreateRun("svc1", time.Now().Add(time.Hour))
	run2, _ := s.CreateRun("svc2", time.Now().Add(time.Hour))

	s.ReserveRequest(run1.ID, 10)
	s.ReserveRequest(run1.ID, 10)

	s.LogRequest(&RequestEntry{RunID: run1.ID, Method: "GET", Path: "/a", StatusCode: 200, Counted: true})
	s.LogRequest(&RequestEntry{RunID: run2.ID, Method: "GET", Path: "/b", StatusCode: 200, Counted: true})

	logs1, _ := s.GetRequestLogs(run1.ID)
	logs2, _ := s.GetRequestLogs(run2.ID)

	if len(logs1) != 1 {
		t.Errorf("expected 1 log for run1, got %d", len(logs1))
	}
	if len(logs2) != 1 {
		t.Errorf("expected 1 log for run2, got %d", len(logs2))
	}

	r1, _ := s.GetRun(run1.ID)
	r2, _ := s.GetRun(run2.ID)
	if r1.RequestsUsed != 2 {
		t.Errorf("expected run1 requests_used=2, got %d", r1.RequestsUsed)
	}
	if r2.RequestsUsed != 0 {
		t.Errorf("expected run2 requests_used=0, got %d", r2.RequestsUsed)
	}
}

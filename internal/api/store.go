package api

import (
	"sort"
	"sync"
	"time"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// recordStatus is the lifecycle of one submitted scan
type recordStatus string

const (
	statusPending recordStatus = "PENDING"
	statusRunning recordStatus = "RUNNING"
	statusDone    recordStatus = "DONE"
	// statusError means the scan could not even be attempted (an invalid
	// target, a scanner-level rejection) - distinct from a *result* whose
	// own Status field is ERROR, which is still a completed submission
	statusError recordStatus = "ERROR"
)

// record is everything the store keeps about one submission. Nothing on
// this type is ever populated from the request's own headers: only the
// decoded target/options and the scanner's output.
type record struct {
	ID        string
	Status    recordStatus
	Result    *model.ScanResult
	Decision  *policy.Decision
	Message   string // set only on statusError, and never from request headers
	CreatedAt time.Time

	// Bytes estimates the encoded result size; unfinished records use zero
	Bytes int64
}

// store keeps bounded, in-memory scan records. Restarts lose data. Eviction
// removes expired and oldest terminal records but never active scans, which
// are bounded separately by maxInFlight.
type store struct {
	mu   sync.Mutex
	data map[string]*record

	retention  time.Duration
	maxRecords int
	maxBytes   int64
	totalBytes int64
}

func newStore(retention time.Duration, maxRecords int, maxBytes int64) *store {
	return &store{data: map[string]*record{}, retention: retention, maxRecords: maxRecords, maxBytes: maxBytes}
}

// put inserts r before evicting so the size calculation includes the new record. A pending
// record is not eligible for eviction while its scan is still running.
func (s *store) put(r *record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[r.ID] = r
	s.totalBytes += r.Bytes
	s.evictLocked()
}

// removeLocked deletes id and keeps totalBytes in step. Called with mu held
func (s *store) removeLocked(id string) {
	if r, ok := s.data[id]; ok {
		s.totalBytes -= r.Bytes
		delete(s.data, id)
	}
}

// evictLocked drops every record older than retention, then - if the store is still at or
// over maxRecords or maxBytes - the oldest remaining ones (oldest CreatedAt first) until
// both are back under their caps
func (s *store) evictLocked() {
	cutoff := time.Now().Add(-s.retention)
	for id, r := range s.data {
		if r.Status != statusPending && r.Status != statusRunning && r.CreatedAt.Before(cutoff) {
			s.removeLocked(id)
		}
	}

	if s.countLocked() < s.maxRecords && s.totalBytes <= s.maxBytes {
		return
	}
	ids := make([]string, 0, len(s.data))
	for id, r := range s.data {
		if r.Status == statusPending || r.Status == statusRunning {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return s.data[ids[i]].CreatedAt.Before(s.data[ids[j]].CreatedAt) })
	// Both counted records already include whatever just triggered this
	// call, so there is no headroom to reserve for it: evict oldest first
	// until under both caps, or until there is nothing left that eviction
	// is allowed to touch
	excess := s.countLocked() - s.maxRecords
	for i := 0; i < len(ids) && (i < excess || s.totalBytes > s.maxBytes); i++ {
		s.removeLocked(ids[i])
	}
}

// get returns a snapshot of the record at this instant, not the live
// pointer: handleGet reads it with no lock held, and the record is
// mutated concurrently by a running scan's goroutine, so handing out the
// pointer itself would be a data race
func (s *store) get(id string) (record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data[id]
	if !ok {
		return record{}, false
	}
	return *r, true
}

// update applies mutate to the stored record for id, if it still has one - a record can
// have been evicted between a scan starting and it finishing, though never while PENDING or
// RUNNING, so every in-progress scan's own updates always land
func (s *store) update(id string, mutate func(*record)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data[id]
	if !ok {
		return
	}
	before := r.Bytes
	mutate(r)
	s.totalBytes += r.Bytes - before
	s.evictLocked()
}

func (s *store) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.countLocked()
}

func (s *store) countLocked() int { return len(s.data) }

// byteCeiling is the total this store keeps across every finished record.
// A caller measuring one result needs it to tell a large result apart from
// one that could never be kept at all.
func (s *store) byteCeiling() int64 { return s.maxBytes }

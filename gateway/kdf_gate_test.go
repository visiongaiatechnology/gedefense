// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestKDFGateRefusesAboveGlobalBudget proves the process-wide KDF budget is a hard
// admission limit: with every slot held, further verifications are refused instead of
// starting another memory-hard Argon2id allocation (FIND-010).
func TestKDFGateRefusesAboveGlobalBudget(t *testing.T) {
	gate := newKDFGate(maxConcurrentKDF)
	gate.queueTimeout = 0
	ctx := context.Background()
	releases := make([]func(), 0, maxConcurrentKDF)
	for i := 0; i < maxConcurrentKDF; i++ {
		release, err := gate.acquire(ctx, fmt.Sprintf("198.51.100.%d", i))
		if err != nil {
			t.Fatalf("slot %d was refused while the budget was free: %v", i, err)
		}
		releases = append(releases, release)
	}
	for i := 0; i < 50; i++ {
		if _, err := gate.acquire(ctx, fmt.Sprintf("203.0.113.%d", i)); !errors.Is(err, errKDFOverloaded) {
			t.Fatalf("verification %d was admitted above the global KDF budget: %v", i, err)
		}
	}
	if inFlight, maxObserved := gate.stats(); inFlight != maxConcurrentKDF || maxObserved > maxConcurrentKDF {
		t.Fatalf("stats while saturated: in-flight=%d max=%d", inFlight, maxObserved)
	}
	for _, release := range releases {
		release()
	}
	if inFlight, _ := gate.stats(); inFlight != 0 {
		t.Fatalf("in-flight=%d after every slot was released", inFlight)
	}
	release, err := gate.acquire(ctx, "203.0.113.200")
	if err != nil {
		t.Fatalf("a released KDF slot was not reusable: %v", err)
	}
	release()
}

// TestKDFGateNeverExceedsGlobalBudgetUnderFiftyConcurrentVerifications runs 50
// admissions at once and asserts that no more than maxConcurrentKDF verifications ever
// hold a slot together, and that the gate drains without a deadlock.
func TestKDFGateNeverExceedsGlobalBudgetUnderFiftyConcurrentVerifications(t *testing.T) {
	gate := newKDFGate(maxConcurrentKDF)
	gate.queueTimeout = 0
	const workers = 50
	var current, peak atomic.Int64
	var granted, refused atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			release, err := gate.acquire(context.Background(), fmt.Sprintf("192.0.2.%d", i))
			if err != nil {
				refused.Add(1)
				return
			}
			granted.Add(1)
			running := current.Add(1)
			for {
				old := peak.Load()
				if running <= old || peak.CompareAndSwap(old, running) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			current.Add(-1)
			release()
		}(i)
	}
	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent KDF admission deadlocked")
	}
	if peak.Load() > maxConcurrentKDF {
		t.Fatalf("%d verifications ran concurrently, budget is %d", peak.Load(), maxConcurrentKDF)
	}
	if _, maxObserved := gate.stats(); maxObserved > maxConcurrentKDF {
		t.Fatalf("gate recorded %d concurrent verifications, budget is %d", maxObserved, maxConcurrentKDF)
	}
	if granted.Load() < int64(maxConcurrentKDF) {
		t.Fatalf("only %d verifications were admitted", granted.Load())
	}
	if inFlight, _ := gate.stats(); inFlight != 0 {
		t.Fatalf("in-flight=%d after all admissions returned", inFlight)
	}
}

// TestKDFGateReservesInflightPerIdentityBeforeVerification proves one source cannot
// occupy the whole budget: its own reservations are limited before any KDF starts,
// while another source still gets a slot.
func TestKDFGateReservesInflightPerIdentityBeforeVerification(t *testing.T) {
	gate := newKDFGate(maxConcurrentKDF)
	gate.queueTimeout = 0
	const identity = "198.51.100.7"
	releases := make([]func(), 0, maxConcurrentKDFPerIdentity)
	for i := 0; i < maxConcurrentKDFPerIdentity; i++ {
		release, err := gate.acquire(context.Background(), identity)
		if err != nil {
			t.Fatalf("identity reservation %d refused: %v", i, err)
		}
		releases = append(releases, release)
	}
	if _, err := gate.acquire(context.Background(), identity); !errors.Is(err, errKDFIdentityBusy) {
		t.Fatalf("a third in-flight attempt from one source was admitted: %v", err)
	}
	other, err := gate.acquire(context.Background(), "198.51.100.8")
	if err != nil {
		t.Fatalf("a second source had no share of the free budget: %v", err)
	}
	other()
	for _, release := range releases {
		release()
	}
	again, err := gate.acquire(context.Background(), identity)
	if err != nil {
		t.Fatalf("identity reservations were not released: %v", err)
	}
	again()
}

// TestKDFGateReleasesReservationWhenContextIsCancelled proves a caller that gives up
// (browser closed, deadline hit) neither keeps a per-identity reservation nor holds a
// slot, so cancellation cannot turn into a permanent denial of service.
func TestKDFGateReleasesReservationWhenContextIsCancelled(t *testing.T) {
	gate := newKDFGate(1)
	gate.queueTimeout = time.Minute
	holder, err := gate.acquire(context.Background(), "holder")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := gate.acquire(ctx, "waiter"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled waiter returned %v, want context deadline error", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("cancelled waiter blocked for %v", elapsed)
	}
	gate.mu.Lock()
	_, stillReserved := gate.active["waiter"]
	gate.mu.Unlock()
	if stillReserved {
		t.Fatal("cancelled verification kept its per-identity reservation")
	}
	holder()
	if inFlight, _ := gate.stats(); inFlight != 0 {
		t.Fatalf("in-flight=%d after the holder released", inFlight)
	}
	gate.queueTimeout = 0
	release, err := gate.acquire(context.Background(), "waiter")
	if err != nil {
		t.Fatalf("the slot was not usable after the cancelled wait: %v", err)
	}
	release()
}

// TestConcurrentSignInsAreBackpressuredBeforeTheKDF drives the real sign-in handler
// with 50 simultaneous attempts. Every attempt either authenticates or is refused with
// 429/503 + Retry-After; the gate's high-water mark shows that no more than
// maxConcurrentKDF verifications ever ran together, and the run completes without a
// deadlock (FIND-010).
func TestConcurrentSignInsAreBackpressuredBeforeTheKDF(t *testing.T) {
	g, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	g.ensureKDF()
	g.kdf.queueTimeout = 0

	resp, err := client.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	csrf := extractCSRF(t, readBody(t, resp))

	const workers = 50
	type outcome struct {
		status     int
		retryAfter string
		err        error
	}
	results := make(chan outcome, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			form := url.Values{"csrf": {csrf}, "password": {"correct horse battery staple"}}
			req, err := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
			if err != nil {
				results <- outcome{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "null")
			req.Header.Set("Sec-Fetch-Site", "none")
			resp, err := client.Do(req)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			results <- outcome{status: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After")}
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(results)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("parallel sign-ins deadlocked")
	}

	successes, rejected := 0, 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("a parallel sign-in failed at the transport layer: %v", result.err)
		}
		switch result.status {
		case http.StatusSeeOther:
			successes++
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			rejected++
			if result.retryAfter == "" {
				t.Fatalf("backpressure status %d has no Retry-After header", result.status)
			}
		default:
			t.Fatalf("unexpected parallel sign-in status %d", result.status)
		}
	}
	if successes == 0 {
		t.Fatal("no parallel sign-in was admitted")
	}
	if rejected == 0 {
		t.Fatalf("%d simultaneous sign-ins were not backpressured", workers)
	}
	if _, maxObserved := g.kdf.stats(); maxObserved > maxConcurrentKDF {
		t.Fatalf("gate recorded %d concurrent KDFs, budget is %d", maxObserved, maxConcurrentKDF)
	}
	if inFlight, _ := g.kdf.stats(); inFlight != 0 {
		t.Fatalf("in-flight=%d after all parallel sign-ins returned", inFlight)
	}
}

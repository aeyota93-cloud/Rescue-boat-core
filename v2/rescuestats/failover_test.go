package rescuestats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ failoverSelector      = (*group.Selector)(nil)
	_ adapter.OutboundGroup = (*group.Selector)(nil)
)

func working(ms int) failoverResult {
	return failoverResult{OK: true, Delay: time.Duration(ms) * time.Millisecond}
}

// time.Time не даёт менять wall отдельно от mono. В тестах копируем только wall
// из другого Add того же начала. ext сохраняет монотонный ход Go 1.25.
// Начало фиксировано; системные часы и ожидание времени не используются.
type testTimeLayout struct {
	wall uint64
	ext  int64
	loc  *time.Location
}
type failoverClock struct {
	mu         sync.Mutex
	base       time.Time
	mono, wall time.Duration
}

func newFailoverClock() *failoverClock {
	base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	seconds := base.Unix() - time.Date(1885, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	layout := (*testTimeLayout)(unsafe.Pointer(&base))
	layout.wall, layout.ext = 1<<63|uint64(seconds)<<30, 1
	return &failoverClock{base: base}
}
func (c *failoverClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	mono, wall := c.base.Add(c.mono), c.base.Add(c.wall)
	(*testTimeLayout)(unsafe.Pointer(&mono)).wall = (*testTimeLayout)(unsafe.Pointer(&wall)).wall
	return mono
}
func (c *failoverClock) advance(mono, wall time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mono += mono
	c.wall += wall
}

func TestFailoverClockIntervals(t *testing.T) {
	c := newFailoverClock()
	before := c.now()
	c.advance(5*time.Second, 25*time.Second)
	after := c.now()
	if after.Sub(before) != 5*time.Second || after.Round(0).Sub(before.Round(0)) != 25*time.Second {
		t.Fatal("fake clock lost independent monotonic and wall intervals")
	}
}

func machineBatch(m *failoverMachine, now time.Time, results map[string]failoverResult) (d failoverDecision, follow bool) {
	b := m.next()
	for _, tag := range b.tags {
		d, follow = m.receive(now, failoverReply{b.generation, tag, results[tag]})
	}
	return
}

func TestFailoverStartMinimumAndTie(t *testing.T) {
	for _, tt := range []struct {
		name   string
		delays []int
		want   string
	}{
		{"minimum", []int{90, 40, 20}, "C"},
		{"tie inclusive", []int{25, 20, 21}, "A"},
		{"outside tie", []int{26, 20, 21}, "B"},
		{"global minimum, no chained ties", []int{30, 25, 20}, "B"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := newFailoverClock().now()
			m := newFailoverMachine([]string{"A", "B", "C"}, "A", now)
			d, _ := machineBatch(m, now, map[string]failoverResult{"A": working(tt.delays[0]), "B": working(tt.delays[1]), "C": working(tt.delays[2])})
			got := d.To
			if got == "" {
				got = m.active
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFailoverStartupRejectsTCPOnly(t *testing.T) {
	now := newFailoverClock().now()
	m := newFailoverMachine([]string{"A", "B"}, "A", now)
	tcp := func(context.Context, string, N.Dialer) (time.Duration, error) { return time.Millisecond, nil }
	udp := func(context.Context, N.Dialer) error { return errors.New("UDP unavailable") }
	tcpOnly := probeFailover(context.Background(), "test", nil, tcp, udp)
	d, _ := machineBatch(m, now, map[string]failoverResult{"A": tcpOnly, "B": working(100)})
	if tcpOnly.OK || d.To != "B" || d.Msg != FailoverMsgStart {
		t.Fatalf("selected TCP-only server: %+v", d)
	}
}

func TestFailoverRuleBothConditionsAndCancellation(t *testing.T) {
	c := newFailoverClock()
	m := newFailoverMachine([]string{"A", "B"}, "A", c.now())
	machineBatch(m, c.now(), map[string]failoverResult{"A": working(10), "B": working(1)})
	// Начальный выбор B применяем, затем отсчитываем поломку от переключения.
	m.switchedTo("B", c.now())
	for i := 1; i <= 4; i++ {
		c.advance(5*time.Second, 5*time.Second)
		m.observe(c.now(), "B", true)
		_, follow := machineBatch(m, c.now(), nil)
		if follow {
			t.Fatalf("broken at %d seconds", i*5)
		}
	}
	if m.failures != 4 {
		t.Fatal(m.failures)
	}
	c.advance(5*time.Second-time.Nanosecond, 5*time.Second-time.Nanosecond)
	if m.broken(c.now()) {
		t.Fatal("broken before 25 seconds")
	}
	c.advance(time.Nanosecond, time.Nanosecond)
	if !m.broken(c.now()) {
		t.Fatal("not broken at exactly 25 seconds")
	}
	m.failures = 3
	if m.broken(c.now()) {
		t.Fatal("broken with fewer than four failures")
	}
	m.lastOK = c.now()
	m.failures = 2
	_, follow := machineBatch(m, c.now(), map[string]failoverResult{"B": {Canceled: true}})
	if follow || m.failures != 2 {
		t.Fatal("cancellation counted as failure")
	}
	_, _ = machineBatch(m, c.now(), map[string]failoverResult{"B": working(10)})
	if m.failures != 0 || m.lastOK != c.now() {
		t.Fatal("success did not reset window")
	}
}

func TestFailoverPauseAndWallClock(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mono, wall time.Duration
		reset      bool
	}{
		{"monotonic pause", 16 * time.Second, 16 * time.Second, true},
		{"wall pause", 5 * time.Second, 16 * time.Second, true},
		{"monotonic boundary", 15 * time.Second, 15 * time.Second, false},
		{"wall boundary", 5 * time.Second, 15 * time.Second, false},
		{"wall backwards", 5 * time.Second, -time.Hour, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newFailoverClock()
			m := newFailoverMachine([]string{"A", "B"}, "A", c.now())
			m.starting = false
			m.failures = 4
			old := m.next()
			c.advance(tt.mono, tt.wall)
			if reset := m.observe(c.now(), "A", true); reset != tt.reset {
				t.Fatalf("reset %v", reset)
			}
			if tt.reset {
				if m.failures != 0 || m.lastOK != c.now() || m.pending != nil {
					t.Fatal("window not reset")
				}
				m.receive(c.now(), failoverReply{old.generation, "A", failoverResult{}})
				if m.failures != 0 {
					t.Fatal("pre-sleep result accepted")
				}
			}
		})
	}
}

func TestFailoverCreditAndMonotonicWindow(t *testing.T) {
	c := newFailoverClock()
	m := newFailoverMachine([]string{"A", "B"}, "A", c.now())
	m.switchedTo("B", c.now())
	m.failures = 4
	for i := 0; i < 4; i++ {
		c.advance(5*time.Second, time.Second)
		m.observe(c.now(), "B", true)
	}
	c.advance(5*time.Second-time.Nanosecond, time.Second)
	if m.broken(c.now()) {
		t.Fatal("credit ended early")
	}
	c.advance(time.Nanosecond, 0)
	if !m.broken(c.now()) {
		t.Fatal("credit depends on wall time")
	}
}

type fakeSelector struct {
	mu        sync.Mutex
	now       string
	selected  []string
	reject    bool
	beforeNow func() // Тест гонки непосредственно перед SelectOutbound.
}

func (s *fakeSelector) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.beforeNow != nil {
		s.beforeNow()
		s.beforeNow = nil
	}
	return s.now
}
func (s *fakeSelector) set(tag string) { s.mu.Lock(); defer s.mu.Unlock(); s.now = tag }
func (s *fakeSelector) SelectOutbound(tag string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reject {
		return false
	}
	s.now = tag
	s.selected = append(s.selected, tag)
	return true
}
func (s *fakeSelector) history() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.selected)
}

type probeCall struct {
	ctx   context.Context
	tag   string
	reply chan failoverResult
}
type machineSnapshot struct {
	active                       string
	starting, searching, pending bool
	failures                     int
	generation                   uint64
}
type failoverHarness struct {
	t       *testing.T
	clock   *failoverClock
	sel     *fakeSelector
	r       *failoverRun
	ticks   chan time.Time
	calls   chan probeCall
	events  chan machineSnapshot
	state   machineSnapshot
	stopped chan struct{}
	live    atomic.Int32
}

func newFailoverHarness(t *testing.T, tags []string, dir string, ignoreCancel bool, initial ...string) *failoverHarness {
	t.Helper()
	h := &failoverHarness{t: t, clock: newFailoverClock(), sel: &fakeSelector{now: tags[0]}, ticks: make(chan time.Time),
		calls: make(chan probeCall, 100), events: make(chan machineSnapshot, 100), stopped: make(chan struct{})}
	if len(initial) > 0 {
		h.sel.now = initial[0]
	}
	check := func(ctx context.Context, tag string) failoverResult {
		h.live.Add(1)
		defer h.live.Add(-1)
		call := probeCall{ctx: ctx, tag: tag, reply: make(chan failoverResult, 1)}
		h.calls <- call
		if ignoreCancel {
			return <-call.reply
		}
		select {
		case result := <-call.reply:
			return result
		case <-ctx.Done():
			return failoverResult{Canceled: ctx.Err() == context.Canceled}
		}
	}
	h.r = newFailoverRun(FailoverOptions{StatsDir: dir, Now: h.clock.now}, h.sel, tags, check,
		func(d time.Duration) (<-chan time.Time, func()) {
			if d != 5*time.Second {
				t.Errorf("interval %v", d)
			}
			return h.ticks, func() { close(h.stopped) }
		})
	h.r.processed = func() {
		m := h.r.machine
		h.events <- machineSnapshot{m.active, m.starting, m.searching, m.pending != nil, m.failures, m.generation}
	}
	h.r.start()
	t.Cleanup(func() {
		h.r.stop()
		if h.live.Load() != 0 {
			t.Error("probe workers still running")
		}
	})
	return h
}
func (h *failoverHarness) collect(n int) map[string]probeCall {
	h.t.Helper()
	calls := make(map[string]probeCall)
	for i := 0; i < n; i++ {
		call := <-h.calls
		if _, duplicate := calls[call.tag]; duplicate {
			h.t.Fatalf("duplicate probe %q", call.tag)
		}
		calls[call.tag] = call
	}
	return calls
}
func (h *failoverHarness) processed(n int) {
	for i := 0; i < n; i++ {
		h.state = <-h.events
	}
}
func (h *failoverHarness) finish(calls map[string]probeCall, results map[string]failoverResult) {
	for tag, call := range calls {
		call.reply <- results[tag]
	}
	h.processed(len(calls))
}
func (h *failoverHarness) tick(mono, wall time.Duration) {
	h.clock.advance(mono, wall)
	h.ticks <- h.clock.now()
	h.processed(1)
}
func (h *failoverHarness) monitor(result failoverResult) {
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(1), map[string]failoverResult{h.state.active: result})
}
func (h *failoverHarness) noSelection() {
	h.t.Helper()
	if got := h.sel.history(); len(got) > 0 {
		h.t.Fatalf("unexpected selection %v", got)
	}
}

func TestFailoverRunStartupRetryAndHealthyMonitoring(t *testing.T) {
	h := newFailoverHarness(t, []string{"A", "B"}, "", false)
	h.finish(h.collect(2), nil)
	h.noSelection()
	if !h.state.starting {
		t.Fatal("stopped startup search without live server")
	}
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(2), nil)
	h.noSelection()
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(2), map[string]failoverResult{"B": working(20)})
	if got := h.sel.history(); !slices.Equal(got, []string{"B"}) {
		t.Fatal(got)
	}
	for i := 0; i < 12; i++ {
		h.tick(5*time.Second, 5*time.Second)
		calls := h.collect(1)
		if _, ok := calls["B"]; !ok {
			t.Fatal("probed inactive server")
		}
		h.finish(calls, map[string]failoverResult{"B": working(100)})
	}
	if got := h.sel.history(); !slices.Equal(got, []string{"B"}) {
		t.Fatal("returned to a faster server", got)
	}
}

func TestFailoverRunStartsOnFirstAndDoesNotLogUnchangedTag(t *testing.T) {
	dir := t.TempDir()
	h := newFailoverHarness(t, []string{"A", "B"}, dir, false, "balance")
	calls := h.collect(2)
	if got := h.sel.history(); !slices.Equal(got, []string{"A"}) {
		t.Fatal("initial selection", got)
	}
	h.finish(calls, nil)
	if h.sel.Now() != "A" || !h.state.starting {
		t.Fatal("did not stay on first server")
	}
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10), "B": working(20)})
	h.r.stop()
	if got := h.sel.history(); !slices.Equal(got, []string{"A"}) {
		t.Fatal("selected unchanged tag", got)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "errors-*.jsonl")); len(files) != 0 {
		t.Fatal("event without startup switch", files)
	}
}

func TestFailoverRunBrokenBatch(t *testing.T) {
	for _, outcome := range []string{"active recovered", "all dead", "candidate"} {
		t.Run(outcome, func(t *testing.T) {
			h := newFailoverHarness(t, []string{"A", "B", "C"}, "", false)
			h.finish(h.collect(3), map[string]failoverResult{"A": working(10), "B": working(20), "C": working(30)})
			for i := 0; i < 5; i++ {
				h.monitor(failoverResult{})
				if i < 4 && h.state.searching {
					t.Fatal("early broken")
				}
			}
			if !h.state.searching {
				t.Fatal("not broken after 25 seconds")
			}
			// Все три вызова уже начались, ни один ещё не завершён.
			calls := h.collect(3)
			results := map[string]failoverResult{}
			switch outcome {
			case "active recovered":
				results["A"], results["B"] = working(100), working(1)
			case "candidate":
				results["B"], results["C"] = working(30), working(10)
			}
			if outcome == "active recovered" {
				// Кандидат уже ответил, активный оживает последним: переход отменяется.
				h.finish(map[string]probeCall{"B": calls["B"], "C": calls["C"]}, results)
				h.noSelection()
				h.finish(map[string]probeCall{"A": calls["A"]}, results)
			} else {
				h.finish(calls, results)
			}
			if outcome == "candidate" {
				if !slices.Equal(h.sel.history(), []string{"C"}) {
					t.Fatal(h.sel.history())
				}
			} else {
				h.noSelection()
			}
			if outcome == "all dead" {
				h.tick(5*time.Second, 5*time.Second)
				h.finish(h.collect(3), map[string]failoverResult{"A": working(100), "B": working(1)})
				h.noSelection()
				if h.state.searching {
					t.Fatal("continued searching after active recovered")
				}
			}
		})
	}
}

func TestFailoverRunFullTimeoutBounds(t *testing.T) {
	h := newFailoverHarness(t, []string{"A", "B"}, "", false)
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
	lastSuccess := h.clock.now()
	for i := 0; i < 5; i++ {
		step := time.Second
		if i == 0 {
			step = 5 * time.Second
		}
		h.tick(step, step)
		calls := h.collect(1)
		h.clock.advance(4*time.Second, 4*time.Second)
		h.finish(calls, nil)
		if i < 4 && h.state.searching {
			t.Fatal("early recognition")
		}
	}
	if !h.state.searching || h.clock.now().Sub(lastSuccess) != 29*time.Second {
		t.Fatal("recognition must be at 29 seconds")
	}
	calls := h.collect(2)
	// Тик в 30 с не создаёт вторую партию поверх подтверждения в 29–33 с.
	h.tick(time.Second, time.Second)
	h.clock.advance(3*time.Second, 3*time.Second)
	h.finish(calls, map[string]failoverResult{"B": working(20)})
	if elapsed := h.clock.now().Sub(lastSuccess); elapsed != 33*time.Second || elapsed > 35*time.Second {
		t.Fatal(elapsed)
	}
	if h.sel.Now() != "B" {
		t.Fatal("no failover by 35 seconds")
	}
}

func TestFailoverRunExternalChangeAndStaleGeneration(t *testing.T) {
	h := newFailoverHarness(t, []string{"A", "B"}, "", true)
	old := h.collect(2)
	h.sel.set("B")
	h.tick(5*time.Second, 5*time.Second)
	if h.state.active != "B" || h.state.starting {
		t.Fatal("external selection not accepted", h.state)
	}
	current := h.collect(1)
	h.finish(old, map[string]failoverResult{"A": working(1)})
	h.noSelection()
	if h.state.failures != 0 || !h.state.pending {
		t.Fatal("stale generation changed state", h.state)
	}
	h.finish(current, map[string]failoverResult{"B": working(100)})
	h.monitor(working(100))
	h.noSelection()
}

func TestFailoverRunPauseDiscardsInflightFailure(t *testing.T) {
	for _, wallOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(wallOnly), func(t *testing.T) {
			h := newFailoverHarness(t, []string{"A", "B"}, "", true)
			h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
			for i := 0; i < 4; i++ {
				h.monitor(failoverResult{})
			}
			h.tick(5*time.Second, 5*time.Second)
			old := h.collect(1)
			mono := 20 * time.Second
			if wallOnly {
				mono = time.Second
			}
			// Результат приходит до тика после пробуждения.
			h.clock.advance(mono, 20*time.Second)
			h.finish(old, nil)
			if h.state.failures != 0 || h.state.searching {
				t.Fatal("sleep counted as breakage", h.state)
			}
			h.finish(h.collect(1), nil)
			h.noSelection()
			if h.state.failures != 1 {
				t.Fatal(h.state)
			}
		})
	}
}

func TestFailoverEventsOnlyOnSuccessfulChange(t *testing.T) {
	dir := t.TempDir()
	h := newFailoverHarness(t, []string{"A", "B"}, dir, false)
	h.sel.reject = true
	h.finish(h.collect(2), map[string]failoverResult{"B": working(10)})
	h.noSelection()
	if files, _ := filepath.Glob(filepath.Join(dir, "errors-*.jsonl")); len(files) != 0 {
		t.Fatal("event after rejected selection")
	}
	h.sel.reject = false
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(2), map[string]failoverResult{"B": working(10)})
	for i := 0; i < 5; i++ {
		h.monitor(failoverResult{})
	}
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
	h.monitor(working(10))
	h.r.stop()
	files, err := filepath.Glob(filepath.Join(dir, "errors-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files %v, %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("events %s", data)
	}
	for i, want := range []struct{ host, msg string }{{"B", "выбран самый быстрый рабочий"}, {"A", "сервер не отвечает 25 с"}} {
		var rec ErrorRecord
		if err := json.Unmarshal([]byte(lines[i]), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.V != 1 || rec.Kind != "failover" || rec.Route != "vpn" || rec.Host != want.host || rec.Msg != want.msg || rec.T == 0 {
			t.Fatalf("record %+v", rec)
		}
	}
}

func TestFailoverApplyChecksSelectorAgain(t *testing.T) {
	now := newFailoverClock().now()
	sel := &fakeSelector{now: "A"}
	r := newFailoverRun(FailoverOptions{Now: func() time.Time { return now }}, sel, []string{"A", "B", "C"}, nil, nil)
	r.machine = newFailoverMachine(r.servers, "A", now)
	sel.beforeNow = func() { sel.now = "C" }
	r.apply(failoverDecision{From: "A", To: "B", Msg: FailoverMsgStart})
	if len(sel.history()) != 0 || r.machine.active != "C" {
		t.Fatal("overwrote external selection")
	}
	r.stop()
}

func TestFailoverCloseWaitsWorkersAndIsIdempotent(t *testing.T) {
	for i := 0; i < 10; i++ {
		h := newFailoverHarness(t, []string{"A", "B"}, "", true)
		calls := h.collect(2)
		f := NewFailover(FailoverOptions{})
		f.active = h.r
		closed := make(chan struct{})
		go func() { _ = f.Close(); close(closed) }()
		for _, call := range calls {
			<-call.ctx.Done()
		}
		select {
		case <-closed:
			t.Fatal("Close returned before workers")
		default:
		}
		for _, call := range calls {
			call.reply <- failoverResult{Canceled: true}
		}
		<-closed
		_ = f.Close()
		h.r.stop()
		if f.Running() || h.live.Load() != 0 {
			t.Fatal("still running")
		}
		select {
		case <-h.stopped:
		default:
			t.Fatal("ticker running")
		}
		if h.r.machine.failures != 0 {
			t.Fatal("shutdown counted as failure")
		}
	}
}

func TestFailoverConcurrencyLimitAndDuplicates(t *testing.T) {
	var tags []string
	for i := 0; i < 12; i++ {
		tags = append(tags, fmt.Sprint(i))
	}
	tags = append(tags, "0", "1")
	h := newFailoverHarness(t, tags, "", false)
	first := h.collect(8)
	if h.live.Load() != 8 {
		t.Fatal("not eight concurrent probes", h.live.Load())
	}
	select {
	case call := <-h.calls:
		t.Fatal("more than eight concurrent probes", call.tag)
	default:
	}
	h.finish(first, nil)
	h.finish(h.collect(4), nil)
	if !h.state.starting {
		t.Fatal("startup ended without working server")
	}
}

func TestFailoverProbeTCPAndUDP(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		tcpOK, udpOK, udpNil bool
		want                 bool
	}{
		{"both", true, true, false, true}, {"TCP only", true, false, false, false},
		{"UDP only", false, true, false, false}, {"neither", false, false, false, false},
		{"UDP pending merge", true, false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan string, 2)
			release := make(chan struct{})
			done := make(chan failoverResult, 1)
			var tcpDeadline time.Time
			tcp := func(ctx context.Context, _ string, _ N.Dialer) (time.Duration, error) {
				tcpDeadline, _ = ctx.Deadline()
				started <- "TCP"
				<-release
				if !tt.tcpOK {
					return 0, errors.New("TCP")
				}
				return 20 * time.Millisecond, nil
			}
			var udpDeadline time.Time
			udp := func(ctx context.Context, _ N.Dialer) error {
				udpDeadline, _ = ctx.Deadline()
				started <- "UDP"
				<-release
				if !tt.udpOK {
					return errors.New("UDP")
				}
				return nil
			}
			if tt.udpNil {
				udp = nil
			}
			go func() { done <- probeFailover(ctx, "test", nil, tcp, udp) }()
			<-started
			if !tt.udpNil {
				<-started
			}
			close(release)
			result := <-done
			if result.OK != tt.want || result.Canceled {
				t.Fatal(result)
			}
			if tcpDeadline.IsZero() || (!tt.udpNil && !tcpDeadline.Equal(udpDeadline)) {
				t.Fatal("different deadlines")
			}
			if tt.tcpOK && result.Delay != 20*time.Millisecond {
				t.Fatal("TCP delay lost")
			}
		})
	}
}

func TestFailoverProbeCanceledVersusDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Time{})
			} else {
				cancel()
			}
			defer cancel()
			tcp := func(ctx context.Context, _ string, _ N.Dialer) (time.Duration, error) { return 0, ctx.Err() }
			udp := func(ctx context.Context, _ N.Dialer) error { return ctx.Err() }
			result := probeFailover(ctx, "test", nil, tcp, udp)
			if result.OK || result.Canceled == deadline {
				t.Fatal(result)
			}
		})
	}
}

func TestFailoverServiceLifecycleAndOneServer(t *testing.T) {
	sel := &fakeSelector{now: "A"}
	for _, tags := range [][]string{nil, {"A"}, {"A", "A"}} {
		if newFailoverRun(FailoverOptions{}, sel, tags, nil, newRealTicker) != nil {
			t.Fatal("run without two distinct servers")
		}
	}
	f := NewFailover(FailoverOptions{SelectTag: "select"})
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart, adapter.StartStateStarted} {
		if err := f.Start(stage); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if f.Running() {
		t.Fatal("running without box")
	}
}

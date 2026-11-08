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

type failoverTestDeadline struct {
	context.Context
	deadline time.Time
	duration time.Duration
	expired  atomic.Bool
	cancel   context.CancelFunc
}

func (c *failoverTestDeadline) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *failoverTestDeadline) Err() error {
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}
func (c *failoverTestDeadline) expire() { c.expired.Store(true); c.cancel() }

type machineSnapshot struct {
	active                       string
	starting, searching, pending bool
	failures                     int
	generation                   uint64
}
type failoverHarness struct {
	t        *testing.T
	clock    *failoverClock
	sel      *fakeSelector
	r        *failoverRun
	ticks    chan time.Time
	calls    chan probeCall
	events   chan machineSnapshot
	state    machineSnapshot
	stopped  chan struct{}
	live     atomic.Int32
	timeouts chan *failoverTestDeadline
	logs     chan string
}

func newFailoverHarness(t *testing.T, tags []string, dir string, ignoreCancel bool, initial ...string) *failoverHarness {
	return newFailoverHarnessWithParent(t, context.Background(), tags, dir, ignoreCancel, initial...)
}

func newFailoverHarnessWithParent(t *testing.T, parent context.Context, tags []string, dir string, ignoreCancel bool, initial ...string) *failoverHarness {
	return newFailoverHarnessWithProbe(t, parent, tags, dir, ignoreCancel, nil, initial...)
}

func newFailoverHarnessWithProbe(t *testing.T, parent context.Context, tags []string, dir string, ignoreCancel bool, wrap func(failoverProbe) failoverProbe, initial ...string) *failoverHarness {
	t.Helper()
	h := &failoverHarness{t: t, clock: newFailoverClock(), sel: &fakeSelector{now: tags[0]}, ticks: make(chan time.Time),
		calls: make(chan probeCall, 100), events: make(chan machineSnapshot, 100), stopped: make(chan struct{}),
		timeouts: make(chan *failoverTestDeadline, 1000), logs: make(chan string, 1000)}
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
	if wrap != nil {
		check = wrap(check)
	}
	h.r = newFailoverRun(parent, FailoverOptions{StatsDir: dir, Now: h.clock.now, Log: func(msg string) { h.logs <- msg }}, h.sel, tags, check,
		func(d time.Duration) (<-chan time.Time, func()) {
			if d != 5*time.Second {
				t.Errorf("interval %v", d)
			}
			return h.ticks, func() { close(h.stopped) }
		})
	h.r.timeout = func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		deadline := &failoverTestDeadline{Context: ctx, deadline: h.clock.now().Add(d), duration: d, cancel: cancel}
		h.timeouts <- deadline
		return deadline, cancel
	}
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

func TestFailoverProbePanicReleasesOrphan(t *testing.T) {
	workers := newFailoverWorkers()
	work := workers.begin("A")
	started, release := make(chan struct{}), make(chan struct{})
	replies, logs := make(chan failoverReply, 1), make(chan string, 2)
	check := func(context.Context, string) failoverResult {
		close(started)
		<-release
		panic("test")
	}
	go runFailoverProbe(context.Background(), check, workers, work, 1, replies, func(msg string) { logs <- msg })
	<-started
	workers.detach(work)
	close(release)
	if reply := <-replies; reply.result.OK || reply.result.Canceled {
		t.Fatal("panic must fail probe", reply)
	}
	if _, live := workers.waiting(); live != 0 || len(workers.orphans) != 0 {
		t.Fatal("panic leaked registry entry", live, workers.orphans)
	}
	if len(logs) != 1 {
		t.Fatal("expected one panic log", len(logs))
	}
}

func TestFailoverRunContinuesAfterProbePanic(t *testing.T) {
	var first atomic.Bool
	h := newFailoverHarnessWithProbe(t, context.Background(), []string{"A", "B"}, "", false,
		func(check failoverProbe) failoverProbe {
			return func(ctx context.Context, tag string) failoverResult {
				result := check(ctx, tag)
				if tag == "A" && !first.Swap(true) {
					panic("test")
				}
				return result
			}
		})
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
	if !h.state.starting || h.orphanCount("A") != 0 {
		t.Fatal(h.state)
	}
	if _, live := h.r.workers.waiting(); live != 0 {
		t.Fatal("leaked worker", live)
	}
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
	if h.state.starting {
		t.Fatal("loop did not continue", h.state)
	}
	h.monitor(working(10))
	h.noSelection()
	panicLogs := 0
	for len(h.logs) > 0 {
		if strings.Contains(<-h.logs, "паника") {
			panicLogs++
		}
	}
	if panicLogs != 1 {
		t.Fatal("expected one panic log", panicLogs)
	}
}

func TestFailoverTransportPanic(t *testing.T) {
	for _, part := range []string{"TCP", "UDP"} {
		t.Run(part, func(t *testing.T) {
			completed := make(chan struct{})
			logs := make(chan string, 2)
			tcp := func(context.Context, string, N.Dialer) (time.Duration, error) {
				if part == "TCP" {
					panic("test")
				}
				close(completed)
				return time.Millisecond, nil
			}
			udp := func(context.Context, N.Dialer) error {
				if part == "UDP" {
					panic("test")
				}
				close(completed)
				return nil
			}
			result := probeFailover(context.Background(), "test", nil, tcp, udp, func(msg string) { logs <- msg })
			if result.OK || result.Canceled {
				t.Fatal("panic must fail transport", result)
			}
			select {
			case <-completed:
			default:
				t.Fatal("other transport did not complete")
			}
			if len(logs) != 1 || !strings.Contains(<-logs, part) {
				t.Fatal("expected one transport panic log")
			}
		})
	}
}

func TestFailoverMaxServers(t *testing.T) {
	tags := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	h := newFailoverHarness(t, tags, "", false)
	if !slices.Equal(h.r.servers, tags[:FailoverMaxServers]) {
		t.Fatal(h.r.servers)
	}
	if len(h.logs) != 1 || !strings.Contains(<-h.logs, "первые 8") {
		t.Fatal("expected one limit log")
	}
	h.finish(h.collect(4), map[string]failoverResult{"A": working(10)})
	h.finish(h.collect(4), nil)
	select {
	case call := <-h.calls:
		t.Fatal("ninth probe started", call.tag)
	default:
	}
	// Внешний выбор за пределами списка не добавляет девятую пробу.
	m := newFailoverMachine(h.r.servers, "I", h.clock.now())
	m.starting, m.searching = false, true
	b := m.next()
	if len(b.tags) != FailoverMaxServers || b.tags[7] != "I" {
		t.Fatal(b.tags)
	}
}

func TestFailoverRunFullTimeoutBounds(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		t.Run(fmt.Sprint("candidate=", candidate), func(t *testing.T) {
			tags := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
			h := newFailoverHarness(t, tags, "", true)
			h.finish(h.collect(4), map[string]failoverResult{"A": working(10)})
			h.finish(h.collect(4), nil)
			lastSuccess := h.clock.now()
			var late []map[string]probeCall
			for i := 0; i < 5; i++ {
				step := time.Second
				if i == 0 {
					step = 5 * time.Second
				}
				h.tick(step, step)
				calls := h.collect(1)
				late = append(late, calls)
				h.expire(calls)
				if i < 4 && h.state.searching {
					t.Fatal("early recognition")
				}
				if i < 4 {
					// Освобождаем сироту поздней удачей, не сбрасывая неудачи.
					h.finish(calls, map[string]failoverResult{"A": working(1)})
					late = late[:len(late)-1]
					if h.state.failures != i+1 {
						t.Fatal("late success reset failures", h.state)
					}
				}
			}
			if !h.state.searching || h.clock.now().Sub(lastSuccess) != 29*time.Second {
				t.Fatal("recognition must be at 29 seconds", h.state)
			}
			calls := h.collect(8)
			h.tick(time.Second, time.Second)
			if candidate {
				// Кандидат ответил, остальные ждут общего срока.
				h.finish(map[string]probeCall{"B": calls["B"]}, map[string]failoverResult{"B": working(20)})
				delete(calls, "B")
			}
			h.clock.advance(3*time.Second, 3*time.Second)
			for _, call := range calls {
				call.ctx.(*failoverTestDeadline).expire()
				break
			}
			h.processed(1)
			if elapsed := h.clock.now().Sub(lastSuccess); elapsed != 33*time.Second || elapsed > 35*time.Second {
				t.Fatal(elapsed)
			}
			if h.state.pending {
				t.Fatal("no decision by deadline", h.state)
			}
			if candidate && h.sel.Now() != "B" {
				t.Fatal("no failover by 35 seconds")
			}
			if !candidate {
				h.noSelection()
			}
			before, history := h.state, h.sel.history()
			late = append(late, calls)
			for _, batch := range late {
				results := make(map[string]failoverResult)
				for tag := range batch {
					results[tag] = working(1)
				}
				h.finish(batch, results)
				if h.state != before || !slices.Equal(history, h.sel.history()) {
					t.Fatal("late replies changed decision", h.state)
				}
			}
		})
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
	r := newFailoverRun(context.Background(), FailoverOptions{Now: func() time.Time { return now }}, sel, []string{"A", "B", "C"}, nil, nil)
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
	first := h.collect(4)
	if h.live.Load() != 4 {
		t.Fatal("not four concurrent startup probes", h.live.Load())
	}
	select {
	case call := <-h.calls:
		t.Fatal("more than four concurrent startup probes", call.tag)
	default:
	}
	h.finish(first, nil)
	h.finish(h.collect(4), nil)
	if !h.state.starting {
		t.Fatal("startup ended without working server")
	}
}

func (h *failoverHarness) expire(calls map[string]probeCall) {
	h.t.Helper()
	for _, call := range calls {
		deadline := call.ctx.(*failoverTestDeadline)
		if deadline.duration != FailoverTimeout {
			h.t.Fatalf("probe timeout %v", deadline.duration)
		}
		h.clock.advance(FailoverTimeout, FailoverTimeout)
		deadline.expire()
		h.processed(1)
		return
	}
	h.t.Fatal("no calls to expire")
}

func (h *failoverHarness) orphanCount(tag string) int {
	h.r.workers.mu.Lock()
	defer h.r.workers.mu.Unlock()
	return h.r.workers.orphans[tag]
}

func (h *failoverHarness) noErrorEvents(dir string) {
	h.t.Helper()
	if files, err := filepath.Glob(filepath.Join(dir, "errors-*.jsonl")); err != nil || len(files) != 0 {
		h.t.Fatalf("unexpected events: %v, %v", files, err)
	}
}

func TestFailoverDeadlineOrphansAndLimit(t *testing.T) {
	h := newFailoverHarness(t, []string{"A", "B"}, "", true)
	first := h.collect(2)
	h.expire(first)
	if h.state.pending || !h.state.starting {
		t.Fatal("deadline did not finish failed startup batch", h.state)
	}
	for _, tag := range []string{"A", "B"} {
		if h.orphanCount(tag) != 1 || first[tag].ctx.Err() == nil {
			t.Fatal("orphan not counted or not canceled", tag)
		}
	}
	h.tick(time.Second, time.Second)
	second := h.collect(2)
	h.expire(second)
	for _, tag := range []string{"A", "B"} {
		if h.orphanCount(tag) != 2 {
			t.Fatal("second orphan not counted", tag)
		}
	}
	h.tick(time.Second, time.Second)
	// При двух сиротах результаты неудачи приходят сразу, без новых вызовов.
	h.processed(2)
	if h.state.pending || !h.state.starting || h.live.Load() != 4 {
		t.Fatal("orphan limit did not finish batch immediately", h.state, h.live.Load())
	}
	select {
	case call := <-h.calls:
		t.Fatal("probe started above orphan limit", call.tag)
	default:
	}
	for _, calls := range []map[string]probeCall{first, second} {
		h.finish(calls, nil)
	}
	for _, tag := range []string{"A", "B"} {
		if h.orphanCount(tag) != 0 {
			t.Fatal("orphan counter leaked", tag)
		}
	}
	h.tick(5*time.Second, 5*time.Second)
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
	if h.state.starting {
		t.Fatal("probes did not resume after orphans exited")
	}
}

func TestFailoverOrphanLimitIsPerTag(t *testing.T) {
	h := newFailoverHarness(t, []string{"A", "B"}, "", true)
	var orphans []probeCall
	for i := 0; i < 2; i++ {
		calls := h.collect(2)
		h.finish(map[string]probeCall{"B": calls["B"]}, nil)
		h.expire(map[string]probeCall{"A": calls["A"]})
		orphans = append(orphans, calls["A"])
		h.tick(time.Second, time.Second)
	}
	h.processed(1)
	current := h.collect(1)
	if _, ok := current["B"]; !ok || h.live.Load() != 3 {
		t.Fatal("orphan limit affected another tag", current)
	}
	h.finish(current, map[string]failoverResult{"B": working(20)})
	if !slices.Equal(h.sel.history(), []string{"B"}) {
		t.Fatal("healthy tag was not selected", h.sel.history())
	}
	for _, call := range orphans {
		h.finish(map[string]probeCall{"A": call}, map[string]failoverResult{"A": working(1)})
	}
	if !slices.Equal(h.sel.history(), []string{"B"}) || h.orphanCount("A") != 0 {
		t.Fatal("late orphan changed selection or leaked")
	}
}

func TestFailoverDeadlineCountsAsFailureAndLateSuccessIsIgnored(t *testing.T) {
	dir := t.TempDir()
	h := newFailoverHarness(t, []string{"A", "B"}, dir, true)
	h.finish(h.collect(2), map[string]failoverResult{"A": working(10)})
	h.tick(5*time.Second, 5*time.Second)
	late := h.collect(1)
	h.expire(late)
	if h.state.pending || h.state.failures != 1 {
		t.Fatal("timeout was treated as cancellation", h.state)
	}
	h.tick(time.Second, time.Second)
	current := h.collect(1)
	h.finish(late, map[string]failoverResult{"A": working(1)})
	if h.state.failures != 1 || !h.state.pending || h.orphanCount("A") != 0 {
		t.Fatal("late success changed current batch", h.state)
	}
	h.finish(current, nil)
	h.noSelection()
	h.r.stop()
	h.noErrorEvents(dir)
}

func TestFailoverLateStartupOrphanCannotSelectOrLogEvent(t *testing.T) {
	dir := t.TempDir()
	h := newFailoverHarness(t, []string{"A", "B"}, dir, true)
	late := h.collect(2)
	h.expire(late)
	h.tick(time.Second, time.Second)
	current := h.collect(2)
	h.finish(late, map[string]failoverResult{"B": working(1)})
	h.noSelection()
	if !h.state.pending || !h.state.starting {
		t.Fatal("late startup result accepted", h.state)
	}
	h.finish(current, map[string]failoverResult{"A": working(10)})
	h.r.stop()
	h.noErrorEvents(dir)
}

func TestFailoverCloseBoundsOrphanWait(t *testing.T) {
	h := newFailoverHarness(t, []string{"A", "B"}, "", true)
	calls := h.collect(2)
	f := NewFailover(FailoverOptions{})
	f.active = h.r
	closed := make(chan struct{})
	go func() { _ = f.Close(); close(closed) }()
	for _, call := range calls {
		<-call.ctx.Done()
	}
	var wait *failoverTestDeadline
	for wait == nil {
		deadline := <-h.timeouts
		if deadline.duration == failoverStopTimeout {
			wait = deadline
		}
	}
	if wait.duration > time.Second {
		t.Fatal("shutdown wait exceeds one second", wait.duration)
	}
	select {
	case <-closed:
		t.Fatal("Close did not give orphans time to finish")
	default:
	}
	wait.expire()
	<-closed
	if f.Running() || h.live.Load() != 2 || h.orphanCount("A") != 1 || h.orphanCount("B") != 1 {
		t.Fatal("Close waited for blocked probes or lost their accounting")
	}
	if msg := <-h.logs; !strings.Contains(msg, "осталось сирот — 2") {
		t.Fatal("missing orphan diagnostic", msg)
	}
	// Даже после ухода владельца сироты завершаются без блокировки отправки.
	idle, _ := h.r.workers.waiting()
	for _, call := range calls {
		call.reply <- working(1)
	}
	<-idle
	if h.orphanCount("A") != 0 || h.orphanCount("B") != 0 {
		t.Fatal("shutdown orphan counter leaked")
	}
	_ = f.Close()
}

func TestFailoverParentCancellationRejectsInflightSuccess(t *testing.T) {
	dir := t.TempDir()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newFailoverHarnessWithParent(t, parent, []string{"A", "B"}, dir, true)
	calls := h.collect(2)
	cancel()
	for _, call := range calls {
		<-call.ctx.Done()
	}
	<-h.stopped
	idle, _ := h.r.workers.waiting()
	for _, call := range calls {
		call.reply <- working(1)
	}
	<-idle
	h.r.stop()
	h.noSelection()
	h.noErrorEvents(dir)
	select {
	case call := <-h.calls:
		t.Fatal("probe started after parent cancellation", call.tag)
	default:
	}
	if !h.r.machine.starting || h.r.machine.failures != 0 {
		t.Fatal("parent cancellation changed decisions")
	}
	select {
	case msg := <-h.logs:
		if msg != "сторож остановлен: осталось сирот — 0" {
			t.Fatal("startup result logged after cancellation", msg)
		}
	default:
	}
}

func TestFailoverCanceledParentDoesNotStart(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	h := newFailoverHarnessWithParent(t, parent, []string{"A", "B"}, "", false, "balance")
	<-h.stopped
	h.r.stop()
	h.noSelection()
	if len(h.calls) != 0 {
		t.Fatal("probe started with canceled parent")
	}
}

func TestFailoverStartupWavesHaveFullDeadlines(t *testing.T) {
	tags := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	h := newFailoverHarness(t, tags, "", true)
	start := h.clock.now()
	var batches []map[string]probeCall
	for _, size := range []int{4, 4} {
		calls := h.collect(size)
		for _, call := range calls {
			deadline, _ := call.ctx.Deadline()
			if deadline.Sub(h.clock.now()) != FailoverTimeout {
				t.Fatal("queued probe lost its full deadline", call.tag)
			}
		}
		select {
		case call := <-h.calls:
			t.Fatal("more than four startup probes", call.tag)
		default:
		}
		batches = append(batches, calls)
		h.expire(calls)
	}
	if h.state.pending || h.clock.now().Sub(start) != 2*FailoverTimeout {
		t.Fatal("wrong total startup deadline", h.state)
	}
	for _, calls := range batches {
		h.finish(calls, nil)
	}
	h.noSelection()
}

func TestFailoverBrokenParallelLimit(t *testing.T) {
	tags := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	h := newFailoverHarness(t, tags, "", false)
	h.finish(h.collect(4), map[string]failoverResult{"A": working(10)})
	h.finish(h.collect(4), nil)
	for i := 0; i < 5; i++ {
		h.monitor(failoverResult{})
	}
	first := h.collect(8)
	if h.live.Load() != 8 || !h.state.searching {
		t.Fatal("broken batch did not start eight probes", h.live.Load(), h.state)
	}
	select {
	case call := <-h.calls:
		t.Fatal("more than eight broken probes", call.tag)
	default:
	}
	h.finish(first, map[string]failoverResult{"H": working(10)})
	if !slices.Equal(h.sel.history(), []string{"H"}) {
		t.Fatal("broken candidate was not selected", h.sel.history())
	}
}

func TestFailoverStartupDiagnosticWithoutSwitch(t *testing.T) {
	dir := t.TempDir()
	h := newFailoverHarness(t, []string{"A", "B", "C"}, dir, false)
	h.finish(h.collect(3), map[string]failoverResult{"A": working(10), "B": working(20)})
	h.noSelection()
	msg := <-h.logs
	for _, want := range []string{"стартовая проверка:", "A: ok, 10 мс", "B: ok, 20 мс", "C: неудача, 0 мс", "выбран: A"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("startup diagnostic %q missing %q", msg, want)
		}
	}
	h.r.stop()
	h.noErrorEvents(dir)
	if msg := <-h.logs; msg != "сторож остановлен: осталось сирот — 0" || len(h.logs) != 0 {
		t.Fatal("more than one startup diagnostic")
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
			ctx, cancel := udpTestTimeout(context.Background(), FailoverTimeout)
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
				ctx, cancel = udpTestTimeout(context.Background(), FailoverTimeout)
				ctx.(*failoverTestDeadline).expire()
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

func TestFailoverTransportOrphanWaitsForBothParts(t *testing.T) {
	for _, blocked := range []string{"TCP", "UDP"} {
		t.Run(blocked, func(t *testing.T) {
			ctx, cancel := udpTestTimeout(context.Background(), FailoverTimeout)
			defer cancel()
			started := make(chan string, 2)
			release := make(chan struct{})
			part := func(name string) {
				started <- name
				if name == blocked {
					<-release
				}
			}
			check := func(ctx context.Context, _ string) failoverResult {
				return probeFailover(ctx, "test", nil,
					func(context.Context, string, N.Dialer) (time.Duration, error) {
						part("TCP")
						return time.Millisecond, nil
					}, func(context.Context, N.Dialer) error { part("UDP"); return nil })
			}
			workers := newFailoverWorkers()
			work := workers.begin("A")
			replies := make(chan failoverReply, 1)
			go runFailoverProbe(ctx, check, workers, work, 1, replies)
			<-started
			<-started
			ctx.(*failoverTestDeadline).expire()
			workers.detach(work)
			idle, count := workers.waiting()
			if count != 1 {
				t.Fatal("transport orphan disappeared before both parts ended")
			}
			select {
			case <-replies:
				t.Fatal("orphan returned while transport is still blocked")
			default:
			}
			close(release)
			<-idle
			result := (<-replies).result
			if result.OK || result.Canceled || len(workers.orphans) != 0 {
				t.Fatal("transport deadline or orphan accounting lost", result)
			}
		})
	}
}

func TestFailoverServiceLifecycleAndOneServer(t *testing.T) {
	sel := &fakeSelector{now: "A"}
	for _, tags := range [][]string{nil, {"A"}, {"A", "A"}} {
		if newFailoverRun(context.Background(), FailoverOptions{}, sel, tags, nil, newRealTicker) != nil {
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

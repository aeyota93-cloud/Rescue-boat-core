package rescuestats

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"
)

// Выход select в ядре — group.Selector: сторож переключает его тем же методом, что clash API.
var (
	_ failoverSelector      = (*group.Selector)(nil)
	_ adapter.OutboundGroup = (*group.Selector)(nil)
)

// alive[i] — отвечает ли сервер i на этой проверке.
func tickWith(m *failoverMachine, alive ...bool) failoverDecision {
	return m.tick(func(i int) bool { return alive[i] })
}

func TestFailoverMachinePrimaryAlive(t *testing.T) {
	m := newFailoverMachine(2)
	for i := 0; i < 10; i++ {
		if d := tickWith(m, true, true); d.To != -1 {
			t.Fatalf("tick %d: switched to %d", i, d.To)
		}
	}
}

func TestFailoverMachineThreeFailures(t *testing.T) {
	m := newFailoverMachine(2)
	// 2 неудачи и удача — счёт сбрасывается.
	for _, alive := range []bool{false, false, true, false, false} {
		if d := tickWith(m, alive, true); d.To != -1 {
			t.Fatalf("early switch to %d", d.To)
		}
	}
	d := tickWith(m, false, true)
	if d.To != 1 || d.Msg != FailoverMsgToBackup {
		t.Fatalf("decision = %+v, want switch to backup", d)
	}
}

func TestFailoverMachineReturn(t *testing.T) {
	m := newFailoverMachine(2)
	for i := 0; i < 3; i++ {
		tickWith(m, false, true)
	}
	if m.active != 1 {
		t.Fatal("not on backup")
	}
	// 2 удачи и неудача — не возвращаемся.
	for _, alive := range []bool{true, true, false, true, true} {
		if d := tickWith(m, alive, true); d.To != -1 {
			t.Fatalf("early return: %+v", d)
		}
	}
	d := tickWith(m, true, true)
	if d.To != 0 || d.Msg != FailoverMsgToPrimary {
		t.Fatalf("decision = %+v, want return", d)
	}
	if m.active != 0 || m.primaryFail != 0 {
		t.Fatalf("state after return: %+v", m)
	}
}

func TestFailoverMachineAllDead(t *testing.T) {
	m := newFailoverMachine(3)
	for i := 0; i < 10; i++ {
		if d := tickWith(m, false, false, false); d.To != -1 {
			t.Fatalf("switch to dead backup %d", d.To)
		}
	}
	if m.active != 0 {
		t.Fatal("left primary")
	}
	// Запасной ожил — переключаемся сразу (основной уже не отвечает давно).
	if d := tickWith(m, false, false, true); d.To != 2 {
		t.Fatalf("decision = %+v, want 2", d)
	}
}

func TestFailoverMachineNextLiveBackup(t *testing.T) {
	m := newFailoverMachine(3)
	var d failoverDecision
	for i := 0; i < 3; i++ {
		d = tickWith(m, false, false, true)
	}
	if d.To != 2 {
		t.Fatalf("decision = %+v, want first live backup 2", d)
	}
	// Активный запасной (2) умер, 1 ожил: через 3 неудачи — на 1.
	for i := 0; i < 2; i++ {
		if d = tickWith(m, false, true, false); d.To != -1 {
			t.Fatalf("early backup switch: %+v", d)
		}
	}
	if d = tickWith(m, false, true, false); d.To != 1 {
		t.Fatalf("decision = %+v, want 1", d)
	}
}

func TestFailoverMachineChecksOnlyNeeded(t *testing.T) {
	m := newFailoverMachine(3)
	var checked []int
	m.tick(func(i int) bool { checked = append(checked, i); return true })
	if len(checked) != 1 || checked[0] != 0 {
		t.Fatalf("checked %v, want only primary", checked)
	}
}

// --- запуск сторожа ---

type fakeSelector struct {
	mu       sync.Mutex
	now      string
	selected []string
}

func (s *fakeSelector) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *fakeSelector) SelectOutbound(tag string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = tag
	s.selected = append(s.selected, tag)
	return true
}

func (s *fakeSelector) history() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.selected...)
}

type fakeHealth struct {
	mu    sync.Mutex
	alive map[string]bool
}

func (h *fakeHealth) set(tag string, ok bool) {
	h.mu.Lock()
	h.alive[tag] = ok
	h.mu.Unlock()
}

func (h *fakeHealth) check(_ context.Context, tag string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.alive[tag]
}

// manualTicker — тики по команде; tick ждёт, пока цикл обработает тик.
type manualTicker struct {
	c       chan time.Time
	done    chan struct{}
	stopped chan struct{}
}

func newManualTicker() *manualTicker {
	return &manualTicker{c: make(chan time.Time), done: make(chan struct{}), stopped: make(chan struct{})}
}

func (m *manualTicker) factory(d time.Duration) (<-chan time.Time, func()) {
	if d != FailoverInterval {
		panic("interval")
	}
	return m.c, func() { close(m.stopped) }
}

func (m *manualTicker) attach(r *failoverRun) {
	r.cycled = func() { m.done <- struct{}{} }
}

func (m *manualTicker) tick(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case m.c <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatal("cycle stuck")
		}
		<-m.done
	}
}

func TestFailoverRunSwitchAndEvent(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.Local)
	sel := &fakeSelector{now: "balance"}
	health := &fakeHealth{alive: map[string]bool{"NL": true, "NL запасной": true}}
	tk := newManualTicker()
	r := newFailoverRun(FailoverOptions{StatsDir: dir, Now: func() time.Time { return at }},
		sel, []string{"NL", "NL запасной"}, health.check, tk.factory)
	if r == nil {
		t.Fatal("no run")
	}
	tk.attach(r)
	r.start()
	if got := sel.history(); len(got) != 1 || got[0] != "NL" {
		t.Fatalf("start selection %v, want NL", got)
	}
	tk.tick(t, 3)
	health.set("NL", false)
	tk.tick(t, 2)
	if len(sel.history()) != 1 {
		t.Fatalf("early switch: %v", sel.history())
	}
	tk.tick(t, 1)
	if got := sel.history(); len(got) != 2 || got[1] != "NL запасной" {
		t.Fatalf("history %v", got)
	}
	health.set("NL", true)
	tk.tick(t, 2)
	if len(sel.history()) != 2 {
		t.Fatalf("early return: %v", sel.history())
	}
	tk.tick(t, 1)
	if got := sel.history(); len(got) != 3 || got[2] != "NL" {
		t.Fatalf("history %v", got)
	}
	r.stop()
	select {
	case <-tk.stopped:
	default:
		t.Error("ticker not stopped")
	}

	data, err := os.ReadFile(filepath.Join(dir, "errors-20261011.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", data)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["v"] != float64(1) || rec["t"] != float64(at.UnixMilli()) || rec["kind"] != "failover" ||
		rec["route"] != "vpn" || rec["host"] != "NL запасной" || rec["msg"] != FailoverMsgToBackup {
		t.Errorf("record %s", lines[0])
	}
	if !strings.Contains(lines[1], `"host":"NL"`) || !strings.Contains(lines[1], FailoverMsgToPrimary) {
		t.Errorf("record %s", lines[1])
	}
}

func TestFailoverRunNotStartedWithOneServer(t *testing.T) {
	sel := &fakeSelector{now: "NL"}
	if newFailoverRun(FailoverOptions{}, sel, []string{"NL"}, nil, newRealTicker) != nil {
		t.Error("run with one server")
	}
	if newFailoverRun(FailoverOptions{}, sel, nil, nil, newRealTicker) != nil {
		t.Error("run without servers")
	}
}

func TestFailoverNoStatsDirNoFile(t *testing.T) {
	sel := &fakeSelector{now: "A"}
	health := &fakeHealth{alive: map[string]bool{"B": true}}
	tk := newManualTicker()
	r := newFailoverRun(FailoverOptions{}, sel, []string{"A", "B"}, health.check, tk.factory)
	tk.attach(r)
	r.start()
	tk.tick(t, 3)
	r.stop()
	if got := sel.history(); len(got) != 1 || got[0] != "B" {
		t.Fatalf("history %v", got)
	}
}

func TestFailoverRunStopNoLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		sel := &fakeSelector{now: "A"}
		health := &fakeHealth{alive: map[string]bool{"A": true}}
		r := newFailoverRun(FailoverOptions{}, sel, []string{"A", "B"}, health.check, newRealTicker)
		r.start()
		r.stop()
		r.stop() // повторно — без паники и ожидания
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines: %d → %d", before, n)
	}
}

// Служба без экземпляра ядра и после Close ничего не держит.
func TestFailoverServiceLifecycle(t *testing.T) {
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
		t.Error("running without box")
	}
}

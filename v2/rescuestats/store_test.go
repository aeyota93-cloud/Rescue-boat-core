package rescuestats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// readLines — все строки файла как JSON-объекты; невалидная строка — провал теста.
func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: invalid JSON line %q: %v", filepath.Base(path), sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

var errorFields = []string{"v", "t", "kind", "app", "host", "ip", "port", "net", "route", "dur_ms", "n", "msg"}

func checkErrorLine(t *testing.T, m map[string]any) {
	t.Helper()
	if m["kind"] == KindSuppressed {
		for _, k := range []string{"v", "t", "kind", "n"} {
			if _, ok := m[k]; !ok {
				t.Errorf("suppressed line without %q: %v", k, m)
			}
		}
		if len(m) != 4 {
			t.Errorf("suppressed line has extra fields: %v", m)
		}
		return
	}
	for _, k := range errorFields {
		if _, ok := m[k]; !ok {
			t.Errorf("error line without %q: %v", k, m)
		}
	}
	if m["v"] != float64(1) {
		t.Errorf("v != 1: %v", m)
	}
	_, hasGap := m["gap_ms"]
	if hasGap != (m["kind"] == KindStall) {
		t.Errorf("gap_ms only for stall: %v", m)
	}
}

func baseTime() time.Time {
	return time.Date(2026, 10, 9, 12, 0, 0, 0, time.Local)
}

func rec(at time.Time, kind, host string) ErrorRecord {
	return ErrorRecord{T: at.UnixMilli(), Kind: kind, App: "chrome.exe", Host: host, IP: "1.2.3.4", Port: 443, Net: "tcp", Route: RouteVPN, Msg: "x"}
}

func TestStoreCollapse(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime())
	s := NewStore(dir, clock.Now)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t0 := clock.Now()
	s.AddError(rec(t0, KindReset, "a.ru"))
	s.AddError(rec(t0.Add(300*time.Millisecond), KindReset, "a.ru"))
	s.AddError(rec(t0.Add(900*time.Millisecond), KindReset, "a.ru"))
	s.AddError(rec(t0.Add(500*time.Millisecond), KindReset, "b.ru"))   // другой host
	s.AddError(rec(t0.Add(600*time.Millisecond), KindTimeout, "a.ru")) // другой kind
	clock.Add(500 * time.Millisecond)
	s.Flush(false) // окно ещё не закончилось — ничего
	path := filepath.Join(dir, "errors-20261009.jsonl")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("written before collapse window ended")
	}
	s.AddError(rec(t0.Add(1200*time.Millisecond), KindReset, "a.ru")) // новое окно
	clock.Add(2 * time.Second)
	s.Flush(false)
	lines := readLines(t, path)
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d: %v", len(lines), lines)
	}
	if lines[0]["host"] != "a.ru" || lines[0]["n"] != float64(3) || lines[0]["t"] != float64(t0.UnixMilli()) {
		t.Errorf("first line should be a.ru n=3 at t0: %v", lines[0])
	}
	for _, m := range lines {
		checkErrorLine(t, m)
	}
	last := lines[3]
	if last["host"] != "a.ru" || last["n"] != float64(1) {
		t.Errorf("event after window must start a new line: %v", last)
	}
}

func TestStoreDailyLimitAndSuppressed(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime())
	s := NewStore(dir, clock.Now)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	t0 := clock.Now()
	for i := 0; i < MaxErrorsPerDay+7; i++ {
		s.AddError(rec(t0.Add(time.Duration(i)*time.Millisecond), KindReset, fmt.Sprintf("h%d.ru", i)))
	}
	s.AddError(rec(t0.Add(time.Hour), KindReset, "same.ru"))
	s.AddError(rec(t0.Add(time.Hour+10*time.Millisecond), KindReset, "same.ru")) // схлопнется: +2 события
	s.Close()
	lines := readLines(t, filepath.Join(dir, "errors-20261009.jsonl"))
	if len(lines) != MaxErrorsPerDay+1 {
		t.Fatalf("want %d lines, got %d", MaxErrorsPerDay+1, len(lines))
	}
	last := lines[len(lines)-1]
	checkErrorLine(t, last)
	if last["kind"] != KindSuppressed || last["n"] != float64(7+2) {
		t.Errorf("want suppressed n=9, got %v", last)
	}
	// После Close ничего не пишется.
	s.AddError(rec(t0.Add(2*time.Hour), KindReset, "late.ru"))
	s.Close()
	if n := len(readLines(t, filepath.Join(dir, "errors-20261009.jsonl"))); n != MaxErrorsPerDay+1 {
		t.Errorf("written after Close: %d lines", n)
	}
}

func TestStoreLimitSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime())
	path := filepath.Join(dir, "errors-20261009.jsonl")
	f, _ := os.Create(path)
	for i := 0; i < MaxErrorsPerDay-1; i++ {
		fmt.Fprintf(f, `{"v":1,"t":1,"kind":"reset","app":"","host":"h","ip":"","port":0,"net":"tcp","route":"vpn","dur_ms":0,"n":1,"msg":""}`+"\n")
	}
	f.Close()
	s := NewStore(dir, clock.Now)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	s.AddError(rec(clock.Now(), KindReset, "one.ru"))
	s.AddError(rec(clock.Now(), KindReset, "two.ru"))
	s.Close()
	lines := readLines(t, path)
	if len(lines) != MaxErrorsPerDay+1 || lines[len(lines)-1]["kind"] != KindSuppressed {
		t.Errorf("limit must count lines written before restart: %d lines, last %v", len(lines), lines[len(lines)-1])
	}
}

func TestStoreRotationByLocalDate(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 10, 9, 23, 59, 59, 0, time.Local)
	clock := newFakeClock(start)
	s := NewStore(dir, clock.Now)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	// Сутки 9-го: лимит выбран, одно событие пропущено.
	s.dayLines = MaxErrorsPerDay
	s.AddError(rec(start, KindReset, "a.ru"))
	s.AddError(rec(start.Add(100*time.Millisecond), KindTLS, "b.ru"))
	s.AddQuality(CountersRecord{V: 1, T: start.UnixMilli(), Type: "counters"}, start)
	clock.Set(start.Add(1500 * time.Millisecond)) // 10-е, 00:00:00.5
	s.AddError(rec(clock.Now(), KindReset, "c.ru"))
	s.AddQuality(CountersRecord{V: 1, T: clock.Now().UnixMilli(), Type: "counters"}, clock.Now())
	clock.Add(2 * time.Second)
	s.Flush(false)
	s.Close()

	old := readLines(t, filepath.Join(dir, "errors-20261009.jsonl"))
	if len(old) != 1 || old[0]["kind"] != KindSuppressed || old[0]["n"] != float64(2) {
		t.Errorf("day 9: want only suppressed n=2, got %v", old)
	}
	cur := readLines(t, filepath.Join(dir, "errors-20261010.jsonl"))
	if len(cur) != 1 || cur[0]["host"] != "c.ru" {
		t.Errorf("day 10: limit must reset, got %v", cur)
	}
	for _, day := range []string{"20261009", "20261010"} {
		if q := readLines(t, filepath.Join(dir, "quality-"+day+".jsonl")); len(q) != 1 {
			t.Errorf("quality-%s: want 1 line, got %d", day, len(q))
		}
	}
}

func TestStoreCleanup(t *testing.T) {
	dir := t.TempDir()
	now := baseTime()         // 2026-10-09
	files := map[string]bool{ // имя → должен остаться
		"errors-20261009.jsonl":  true,
		"errors-20261002.jsonl":  true, // 7 дней назад
		"errors-20261001.jsonl":  false,
		"errors-20250101.jsonl":  false,
		"quality-20260909.jsonl": true, // 30 дней назад
		"quality-20260908.jsonl": false,
		"quality-20261001.jsonl": true,
		"errors-bad.jsonl":       true, // не наш формат — не трогаем
		"notes.txt":              true,
	}
	for name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	clock := newFakeClock(now)
	s := NewStore(dir, clock.Now)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	check := func(stage string) {
		for name, keep := range files {
			_, err := os.Stat(filepath.Join(dir, name))
			if exists := err == nil; exists != keep {
				t.Errorf("%s: %s exists=%v, want %v", stage, name, exists, keep)
			}
		}
	}
	check("start")
	// Через сутки (сборщик работает): при смене даты удаляется ещё один день.
	files["errors-20261002.jsonl"] = false
	files["quality-20260909.jsonl"] = false
	clock.Add(24 * time.Hour)
	s.Flush(false)
	check("next day")
}

func TestQualityLineFormat(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime())
	s := NewStore(dir, clock.Now)
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	ms := 48
	at := clock.Now()
	s.AddQuality(ProbeRecord{V: 1, T: at.UnixMilli(), Type: "probe", Path: "vpn", Samples: []*int{&ms, nil}}, at)
	s.AddQuality(CountersRecord{V: 1, T: at.UnixMilli(), Type: "counters", Conns: 3, Errs: 1, DNSOk: 2}, at)
	raw, _ := os.ReadFile(filepath.Join(dir, "quality-20261009.jsonl"))
	want := fmt.Sprintf(`{"v":1,"t":%d,"type":"probe","path":"vpn","samples":[48,null]}`+"\n"+
		`{"v":1,"t":%d,"type":"counters","conns":3,"errs":1,"dns_ok":2,"dns_fail":0}`+"\n", at.UnixMilli(), at.UnixMilli())
	if string(raw) != want {
		t.Errorf("quality lines:\n%s\nwant:\n%s", raw, want)
	}
}

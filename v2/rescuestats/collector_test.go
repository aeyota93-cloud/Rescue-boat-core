package rescuestats

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// --- подделки outbound ---

type fakeOutbound struct {
	adapter.Outbound
	tag, typ string
}

func (o *fakeOutbound) Tag() string  { return o.tag }
func (o *fakeOutbound) Type() string { return o.typ }

type fakeGroup struct {
	fakeOutbound
	now string
}

func (g *fakeGroup) Now() string   { return g.now }
func (g *fakeGroup) All() []string { return []string{g.now} }
func (g *fakeGroup) Type() string  { return C.TypeSelector }
func (g *fakeGroup) Tag() string   { return g.tag }

type fakeOutbounds struct {
	adapter.OutboundManager
	list []adapter.Outbound
	def  adapter.Outbound
}

func (f *fakeOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	for _, o := range f.list {
		if o.Tag() == tag {
			return o, true
		}
	}
	return nil, false
}
func (f *fakeOutbounds) Default() adapter.Outbound     { return f.def }
func (f *fakeOutbounds) Outbounds() []adapter.Outbound { return f.list }

type testEnv struct {
	dir     string
	clock   *fakeClock
	run     *run
	vless   *fakeOutbound
	direct  *fakeOutbound
	block   *fakeOutbound
	selectG *fakeGroup
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{dir: t.TempDir(), clock: newFakeClock(baseTime())}
	e.vless = &fakeOutbound{tag: "Мой сервер", typ: C.TypeVLESS}
	e.direct = &fakeOutbound{tag: "direct §hide§", typ: C.TypeDirect}
	e.block = &fakeOutbound{tag: "block", typ: C.TypeBlock}
	e.selectG = &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, now: "Мой сервер"}
	obs := &fakeOutbounds{list: []adapter.Outbound{e.selectG, e.vless, e.direct, e.block}, def: e.selectG}
	e.run = newRun(Options{Dir: e.dir, VPNOutbound: "select", DirectOutbound: "direct §hide§", Now: e.clock.Now}, obs)
	e.run.ctx, e.run.cancel = context.WithCancel(context.Background())
	t.Cleanup(e.run.cancel)
	if err := e.run.store.Open(); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *testEnv) errorLines(t *testing.T) []map[string]any {
	t.Helper()
	e.run.store.Flush(true)
	path := filepath.Join(e.dir, "errors-"+dayOf(e.clock.Now())+".jsonl")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	lines := readLines(t, path)
	for _, m := range lines {
		checkErrorLine(t, m)
	}
	return lines
}

func chromeMetadata() adapter.InboundContext {
	return adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddrHostPort("127.0.0.1", 50000),
		Destination: M.ParseSocksaddrHostPort("213.180.204.211", 443),
		Domain:      "kinopoisk.ru",
		ProcessInfo: &adapter.ConnectionOwner{ProcessPath: `C:\Program Files\Google\Chrome\chrome.exe`},
	}
}

func ctxWithID(id uint32, at time.Time) context.Context {
	return log.ContextWithID(context.Background(), log.ID{ID: id, CreatedAt: at})
}

// --- тесты ---

func TestEmptyDirDisabled(t *testing.T) {
	if c := New(Options{Dir: ""}); c != nil {
		t.Fatal("collector must be nil without dir")
	}
	// Без службы ядра сборщик ничего не делает и соединения не трогает.
	dir := filepath.Join(t.TempDir(), "stats")
	c := New(Options{Dir: dir})
	for _, stage := range adapter.ListStartStages {
		if err := c.Start(stage); err != nil {
			t.Fatal(err)
		}
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := c.RoutedConnection(context.Background(), a, chromeMetadata(), nil, nil); got != a {
		t.Error("inactive collector must not wrap connections")
	}
	_ = c.Close()
	_ = c.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("inactive collector must not create files")
	}
}

func TestConnErrorRecord(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	t0 := e.clock.Now()
	info := r.register(ctxWithID(42, t0), chromeMetadata(), "tcp", e.selectG)
	info.established.Store(t0.UnixNano())
	info.down.Store(1000)
	e.clock.Add(850 * time.Millisecond)
	r.connError(info, "connection download closed: read: connection reset by peer", nil)
	r.connError(info, "connection upload closed: write: broken pipe", nil) // вторая причина не пишется
	lines := e.errorLines(t)
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %v", lines)
	}
	m := lines[0]
	want := map[string]any{
		"v": float64(1), "t": float64(t0.Add(850 * time.Millisecond).UnixMilli()), "kind": KindReset,
		"app": "chrome.exe", "host": "kinopoisk.ru", "ip": "213.180.204.211", "port": float64(443),
		"net": "tcp", "route": RouteVPN, "dur_ms": float64(850), "n": float64(1),
		"msg": "read: connection reset by peer",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	c := r.takeCounters(e.clock.Now())
	if c.Conns != 1 || c.Errs != 1 {
		t.Errorf("counters: %+v", c)
	}
}

func TestConnErrorFilters(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	md := chromeMetadata()

	afterData := r.register(context.Background(), md, "tcp", e.direct)
	afterData.down.Store(500)
	r.connError(afterData, "", errors.New("unexpected EOF")) // EOF после данных — норма

	program := r.register(context.Background(), md, "tcp", e.direct)
	r.connError(program, "connection upload closed: read tcp 127.0.0.1:12334->127.0.0.1:50000: wsarecv: An existing connection was forcibly closed by the remote host.", nil)

	canceled := r.register(context.Background(), md, "tcp", e.direct)
	r.connError(canceled, "", context.Canceled)

	if lines := e.errorLines(t); len(lines) != 0 {
		t.Fatalf("ignorable errors written: %v", lines)
	}

	md.Domain = "eof.example"
	noData := r.register(context.Background(), md, "tcp", e.direct)
	r.connError(noData, "", errors.New("EOF"))
	md.Domain = "blocked.example"
	blocked := r.register(context.Background(), md, "tcp", e.block)
	r.connError(blocked, "", errors.New("blocked"))
	lines := e.errorLines(t)
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %v", lines)
	}
	// Порядок строк с одинаковым временем не гарантирован — ищем по сайту.
	byHost := map[any]map[string]any{}
	for _, l := range lines {
		byHost[l["host"]] = l
	}
	if l := byHost["eof.example"]; l["kind"] != KindEOF || l["route"] != RouteDirect || l["dur_ms"] != float64(0) {
		t.Errorf("eof before data: %v", l)
	}
	if l := byHost["blocked.example"]; l["route"] != RouteBlock {
		t.Errorf("block route: %v", l)
	}
}

func TestTrackedConnHandshake(t *testing.T) {
	e := newTestEnv(t)
	c := &Collector{opts: e.run.opts}
	c.active.Store(e.run)

	// Неудачный dial: sing-box зовёт CloseOnHandshakeFailure у обёрнутого соединения.
	a, b := net.Pipe()
	defer b.Close()
	conn := c.RoutedConnection(ctxWithID(7, e.clock.Now()), a, chromeMetadata(), nil, e.selectG)
	if conn == a {
		t.Fatal("active collector must wrap connections")
	}
	_ = N.CloseOnHandshakeFailure(conn, nil, errors.New("open connection to 213.180.204.211:443 using outbound/vless[Мой сервер]: dial tcp 127.0.0.1:9: connectex: No connection could be made because the target machine actively refused it."))
	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("connection must be closed after handshake failure")
	}

	// Успешное соединение: время установления запоминается, счётчики идут.
	x, y := net.Pipe()
	defer y.Close()
	md := chromeMetadata()
	md.Domain = "ok.example"
	conn2 := c.RoutedConnection(ctxWithID(8, e.clock.Now()), x, md, nil, e.direct)
	if err := N.ReportConnHandshakeSuccess(conn2, nil); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = y.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := conn2.Read(buf); err != nil {
		t.Fatal(err)
	}
	info := e.run.lookupID(8)
	if info == nil || info.established.Load() == 0 || info.up.Load() != 5 {
		t.Fatalf("tracking failed: %+v", info)
	}
	_ = conn2.Close()
	_ = conn2.Close()
	if info.closedAt.Load() == 0 {
		t.Error("close not tracked")
	}

	lines := e.errorLines(t)
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %v", lines)
	}
	m := lines[0]
	if m["kind"] != KindRefused || m["dur_ms"] != float64(0) || m["route"] != RouteVPN || m["app"] != "chrome.exe" {
		t.Errorf("dial failure line: %v", m)
	}
	if m["msg"] != "dial tcp 127.0.0.1:9: connectex: No connection could be made because the target machine actively refused it." {
		t.Errorf("msg: %v", m["msg"])
	}
}

func TestTrackedPacketConnHandshakeFailure(t *testing.T) {
	e := newTestEnv(t)
	c := &Collector{opts: e.run.opts}
	c.active.Store(e.run)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	md := chromeMetadata()
	md.Network = N.NetworkUDP
	conn := c.RoutedPacketConnection(ctxWithID(9, e.clock.Now()), bufio.NewPacketConn(pc), md, nil, e.selectG)
	_ = N.CloseOnHandshakeFailure(conn, nil, errors.New("listen packet connection using  outbound/vless[x]: i/o timeout"))
	lines := e.errorLines(t)
	if len(lines) != 1 || lines[0]["net"] != "udp" || lines[0]["kind"] != KindTimeout {
		t.Fatalf("udp dial failure: %v", lines)
	}
}

func TestLogLines(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	t0 := e.clock.Now()
	info := r.register(ctxWithID(4242, t0), chromeMetadata(), "tcp", e.selectG)
	info.established.Store(t0.UnixNano())
	format := func(id uint32, level log.Level, tag, msg string) string {
		f := log.Formatter{BaseTime: t0, DisableLineBreak: true} // как у журнала службы (с цветами)
		ctx := context.Background()
		if id != 0 {
			ctx = ctxWithID(id, t0)
		}
		return f.Format(ctx, level, tag, msg, t0.Add(12*time.Second))
	}

	if id, ok, text := parseLogLine(format(4242, log.LevelError, "connection", "x")); !ok || id != 4242 || text != "connection: x" {
		t.Fatalf("parseLogLine: %d %v %q", id, ok, text)
	}

	// ошибка установленного соединения — по номеру
	r.handleLog(log.LevelError, format(4242, log.LevelError, "connection", "connection download closed: read tcp 10.0.0.2:5555->1.2.3.4:443: read: connection timed out"))
	// чужой номер и строки без номера — пропуск
	r.handleLog(log.LevelError, format(777, log.LevelError, "connection", "connection download closed: read: connection reset by peer"))
	r.handleLog(log.LevelError, format(0, log.LevelError, "outbound/vless[x]", "dial: refused"))
	// DNS: два запроса программы, один неудачный; lookup — удачный и неудачный
	r.handleLog(log.LevelDebug, format(100, log.LevelDebug, "dns", "exchange www.google.com. IN A"))
	r.handleLog(log.LevelDebug, format(101, log.LevelDebug, "dns", "exchange nope.example. IN AAAA"))
	r.handleLog(log.LevelError, format(101, log.LevelError, "dns", "exchange dns-remote failed for nope.example. IN AAAA: context deadline exceeded"))
	r.handleLog(log.LevelDebug, format(102, log.LevelDebug, "dns", "lookup domain ya.ru"))
	r.handleLog(log.LevelDebug, format(103, log.LevelDebug, "dns", "lookup domain bad.example"))
	r.handleLog(log.LevelError, format(103, log.LevelError, "dns", "lookup failed for bad.example: no such host"))
	// собственный замер — не считается
	own := r.ownContext()
	ownID, _ := log.IDFromContext(own)
	r.handleLog(log.LevelDebug, format(ownID.ID, log.LevelDebug, "dns", "lookup domain cp.cloudflare.com"))
	r.handleLog(log.LevelError, format(ownID.ID, log.LevelError, "dns", "exchange dns-direct failed for cp.cloudflare.com. IN A: timeout"))

	lines := e.errorLines(t)
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %v", lines)
	}
	var conn, dns map[string]any
	for _, m := range lines {
		if m["kind"] == KindDNS {
			dns = m
		} else {
			conn = m
		}
	}
	if conn == nil || conn["kind"] != KindTimeout || conn["host"] != "kinopoisk.ru" || conn["msg"] != "read tcp 10.0.0.2:5555->1.2.3.4:443: read: connection timed out" {
		t.Errorf("connection line: %v", conn)
	}
	if dns == nil || dns["host"] != "nope.example" || dns["route"] != RouteVPN || dns["net"] != "udp" {
		t.Errorf("dns line: %v", dns)
	}
	c := r.takeCounters(e.clock.Now())
	if c.DNSOk != 2 || c.DNSFail != 2 {
		t.Errorf("dns counters: ok=%d fail=%d, want 2/2", c.DNSOk, c.DNSFail)
	}
}

func TestStallThroughMaintain(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	md := chromeMetadata()
	md.Network = N.NetworkUDP
	md.Domain = "discord.media"
	info := r.register(context.Background(), md, "udp", e.selectG)
	step := func(up, down int64) {
		info.up.Store(up)
		info.down.Store(down)
		r.maintain()
		e.clock.Add(StallPoll)
	}
	// плотный поток: данные приходят в каждый опрос (иначе это не «замирание»)
	for i := 1; i <= 8; i++ {
		step(int64(i*100), int64(i*100))
	}
	for i := 0; i < 8; i++ { // 2 с без ответа, программа шлёт
		step(int64(900+i*100), 800)
	}
	step(1700, 900)
	e.clock.Add(2 * time.Second)
	lines := e.errorLines(t)
	if len(lines) != 1 {
		t.Fatalf("want 1 stall, got %v", lines)
	}
	m := lines[0]
	if m["kind"] != KindStall || m["gap_ms"] != float64(2250) || m["net"] != "udp" || m["host"] != "discord.media" {
		t.Errorf("stall line: %v", m)
	}
}

func TestQualityCycle(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	r.conns.Store(5)
	r.errs.Store(1)
	probe := func(ctx context.Context, link string, dialer N.Dialer) (time.Duration, error) {
		if link != defaultProbeURL {
			t.Errorf("link %q", link)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("probe without timeout")
		}
		switch dialer {
		case e.selectG:
			return 0, errors.New("dial tcp 127.0.0.1:9: connection refused")
		case e.direct:
			return 12 * time.Millisecond, nil
		}
		t.Errorf("unexpected dialer %v", dialer)
		return 0, errors.New("?")
	}
	r.qualityCycle(probe)
	at := e.clock.Now().UnixMilli()
	raw, err := os.ReadFile(filepath.Join(e.dir, "quality-"+dayOf(e.clock.Now())+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	want := "" +
		`{"v":1,"t":` + itoa(at) + `,"type":"probe","path":"vpn","samples":[null,null,null,null,null]}` + "\n" +
		`{"v":1,"t":` + itoa(at) + `,"type":"probe","path":"direct","samples":[12,12,12,12,12]}` + "\n" +
		`{"v":1,"t":` + itoa(at) + `,"type":"counters","conns":5,"errs":1,"dns_ok":0,"dns_fail":0}` + "\n"
	if string(raw) != want {
		t.Errorf("quality file:\n%s\nwant:\n%s", raw, want)
	}
	if lines := e.errorLines(t); len(lines) != 0 {
		t.Errorf("probes must not produce errors: %v", lines)
	}
}

func TestRunStartStopNoLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		e := newTestEnv(t)
		e.run.cancel()
		e.run.start(nil)
		e.run.stop()
		e.run.stop()
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines leaked: before %d, after %d", before, n)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func TestQualityCycleNoProbe(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	r.opts.NoProbe = true // rescue-stats-probe: false
	r.conns.Store(2)
	r.qualityCycle(func(context.Context, string, N.Dialer) (time.Duration, error) {
		t.Error("probe must not run")
		return 0, nil
	})
	lines := readLines(t, filepath.Join(e.dir, "quality-"+dayOf(e.clock.Now())+".jsonl"))
	if len(lines) != 1 || lines[0]["type"] != "counters" || lines[0]["conns"] != float64(2) {
		t.Fatalf("want only counters, got %v", lines)
	}
}

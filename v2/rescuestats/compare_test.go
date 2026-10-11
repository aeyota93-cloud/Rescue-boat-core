package rescuestats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// --- подделки ---

// cmpServer — локальный TLS-сервер; log общий у обеих «дорог», чтобы видеть поочерёдность.
type cmpServer struct {
	*httptest.Server
	name  string
	log   *cmpLog
	slow  func(n int) time.Duration // задержка ответа на n-й запрос (с нуля)
	count atomic.Int32
	sni   atomic.Value // string
}

type cmpLog struct {
	mu       sync.Mutex
	events   []string
	inflight atomic.Int32
	maxInfl  atomic.Int32
}

func (l *cmpLog) add(s string) {
	l.mu.Lock()
	l.events = append(l.events, s)
	l.mu.Unlock()
}

func (l *cmpLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func newCmpServer(t *testing.T, name string, log *cmpLog, keepAlive bool) *cmpServer {
	t.Helper()
	s := &cmpServer{name: name, log: log}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(s.count.Add(1)) - 1
		cur := log.inflight.Add(1)
		for {
			m := log.maxInfl.Load()
			if cur <= m || log.maxInfl.CompareAndSwap(m, cur) {
				break
			}
		}
		defer log.inflight.Add(-1)
		if r.TLS != nil {
			s.sni.Store(r.TLS.ServerName)
		}
		if r.Method != http.MethodHead || r.Header.Get("Connection") != "keep-alive" {
			t.Errorf("%s: неожиданный запрос %s, Connection=%q", name, r.Method, r.Header.Get("Connection"))
		}
		log.add(name)
		if s.slow != nil {
			time.Sleep(s.slow(n))
		}
		w.WriteHeader(http.StatusOK)
	}))
	s.Config.SetKeepAlivesEnabled(keepAlive)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// fakeDialer — N.Dialer: все соединения идут на addr (пусто — отказ).
type fakeDialer struct {
	addr  string
	delay time.Duration
	mu    sync.Mutex
	dests []M.Socksaddr
	dials atomic.Int32
}

func (d *fakeDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	d.dests = append(d.dests, dest)
	d.mu.Unlock()
	d.dials.Add(1)
	if d.addr == "" {
		return nil, errors.New("connection refused")
	}
	if d.delay > 0 {
		select {
		case <-time.After(d.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

func (d *fakeDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("не нужен")
}

func (d *fakeDialer) destinations() []M.Socksaddr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]M.Socksaddr(nil), d.dests...)
}

var _ N.Dialer = (*fakeDialer)(nil)

// cmpTempDir — как t.TempDir, но удаление повторяется: на Windows антивирус ненадолго держит
// только что переписанные res-файлы, и t.TempDir падает с «directory is not empty».
func cmpTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rescue-compare-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for i := 0; i < 40; i++ {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Logf("временная папка не удалена: %v", err)
	})
	return dir
}

type cmpEnv struct {
	dir    string
	run    *compareRun
	direct *fakeDialer
	vpn    *fakeDialer
	pings  atomic.Int32
	tests  atomic.Int32
}

func newCmpEnv(t *testing.T) *cmpEnv {
	t.Helper()
	e := &cmpEnv{dir: cmpTempDir(t), direct: &fakeDialer{}, vpn: &fakeDialer{}}
	e.run = newCompareRunBase(CompareOptions{Dir: e.dir, TestURL: "http://test.invalid/", Now: func() time.Time { return time.UnixMilli(1791640000000) }})
	e.run.vpnDialer = func() N.Dialer { return e.vpn }
	e.run.directDialer = func() N.Dialer { return e.direct }
	e.run.resolve = func(ctx context.Context, host string) (netip.Addr, error) {
		return netip.MustParseAddr("93.184.216.34"), nil
	}
	e.run.ping = func(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, error) {
		n := e.pings.Add(1)
		return time.Duration(20+n) * time.Millisecond, nil
	}
	e.run.urlTest = func(ctx context.Context, link string, dialer N.Dialer) (time.Duration, error) {
		if link != "http://test.invalid/" {
			t.Errorf("urltest link = %q", link)
		}
		if dialer != N.Dialer(e.vpn) {
			t.Errorf("urltest не через VPN-выход")
		}
		n := e.tests.Add(1)
		return time.Duration(10+n) * time.Millisecond, nil
	}
	e.run.pause = 0
	e.run.timeout = 400 * time.Millisecond
	e.run.scanEvery = 10 * time.Millisecond
	e.run.ctx, e.run.cancel = context.WithCancel(context.Background())
	t.Cleanup(e.run.cancel)
	return e
}

func (e *cmpEnv) request(t *testing.T, req CompareRequest) {
	t.Helper()
	req.V = CompareFormatVersion
	data, _ := json.Marshal(req)
	if err := os.WriteFile(compareReqPath(e.dir, req.ID), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *cmpEnv) readResult(t *testing.T, id string) *CompareResult {
	t.Helper()
	data, err := os.ReadFile(compareResPath(e.dir, id))
	if err != nil {
		t.Fatal(err)
	}
	var res CompareResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("res не разбирается: %v\n%s", err, data)
	}
	return &res
}

// measure выполняет запрос целиком (без сканера); id по умолчанию abcd1234.
func (e *cmpEnv) measure(t *testing.T, req CompareRequest) *CompareResult {
	t.Helper()
	if req.ID == "" {
		req.ID = "abcd1234"
	}
	e.request(t, req)
	e.run.process(req.ID)
	return e.readResult(t, req.ID)
}

func hostPort(s *cmpServer) string { return strings.TrimPrefix(s.URL, "https://") }

func nils(s []*int) int {
	n := 0
	for _, v := range s {
		if v == nil {
			n++
		}
	}
	return n
}

func fmtSamples(s []*int) string {
	parts := make([]string, len(s))
	for i, v := range s {
		if v == nil {
			parts[i] = "null"
		} else {
			parts[i] = fmt.Sprint(*v)
		}
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// --- разбор запроса ---

func TestParseCompareRequest(t *testing.T) {
	ok := func(s string) *CompareRequest {
		t.Helper()
		req, err := ParseCompareRequest("k3j9x0a1", []byte(s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		return req
	}
	req := ok(`{"v":1,"id":"k3j9x0a1","target":"www.example.com","port":443,"count":10,"created":1791640000000}`)
	if req.Target != "www.example.com" || req.Port != 443 || req.Count != 10 {
		t.Errorf("полный запрос: %+v", req)
	}
	req = ok(`{"v":1,"id":"k3j9x0a1","target":"  WWW.Example.COM. "}`)
	if req.Target != "www.example.com" || req.Port != 443 || req.Count != 10 {
		t.Errorf("значения по умолчанию: %+v", req)
	}
	if req = ok(`{"v":1,"id":"k3j9x0a1","target":"1.2.3.4","count":1}`); req.Count != 3 {
		t.Errorf("count снизу: %d", req.Count)
	}
	if req = ok(`{"v":1,"id":"k3j9x0a1","target":"1.2.3.4","count":99}`); req.Count != 30 {
		t.Errorf("count сверху: %d", req.Count)
	}
	if req = ok(`{"v":1,"id":"k3j9x0a1","target":"2001:db8::1","port":27015}`); req.Target != "2001:db8::1" || req.Port != 27015 {
		t.Errorf("ipv6: %+v", req)
	}
	if req = ok(`{"v":1,"id":"k3j9x0a1","target":"пример.рф"}`); req.Target != "xn--e1afmkfd.xn--p1ai" {
		t.Errorf("idn: %q", req.Target)
	}

	bad := map[string]string{
		"не json":            `{`,
		"версия":             `{"v":2,"id":"k3j9x0a1","target":"a.com"}`,
		"нет версии":         `{"id":"k3j9x0a1","target":"a.com"}`,
		"другой id":          `{"v":1,"id":"zzzzzzzz","target":"a.com"}`,
		"нет цели":           `{"v":1,"id":"k3j9x0a1","target":""}`,
		"схема":              `{"v":1,"id":"k3j9x0a1","target":"https://a.com"}`,
		"путь":               `{"v":1,"id":"k3j9x0a1","target":"a.com/x"}`,
		"пробел":             `{"v":1,"id":"k3j9x0a1","target":"a b.com"}`,
		"отрицательный порт": `{"v":1,"id":"k3j9x0a1","target":"a.com","port":-1}`,
		"порт слишком":       `{"v":1,"id":"k3j9x0a1","target":"a.com","port":70000}`,
		"домен с портом":     `{"v":1,"id":"k3j9x0a1","target":"a.com:443"}`,
	}
	for name, body := range bad {
		if _, err := ParseCompareRequest("k3j9x0a1", []byte(body)); err == nil {
			t.Errorf("%s: ошибки нет", name)
		}
	}
}

func TestCompareFileID(t *testing.T) {
	for name, want := range map[string]bool{
		"req-k3j9x0a1.json":     true,
		"req-short.json":        false,
		"req-K3J9X0A1.json":     false,
		"req-k3j9x0a1.json.tmp": false,
		"res-k3j9x0a1.json":     false,
	} {
		if _, ok := compareFileID(name, reqPrefix); ok != want {
			t.Errorf("%s: %v, ждали %v", name, ok, want)
		}
	}
}

// --- tls ---

func TestCompareTLSAlternatesPaths(t *testing.T) {
	e := newCmpEnv(t)
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, true)
	vs := newCmpServer(t, "vpn", log, true)
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)

	res := e.measure(t, CompareRequest{Target: "example.test", Count: 5})
	if !res.Done || res.Error != "" || res.Method != MethodTLS {
		t.Fatalf("итог: %+v", res)
	}
	if res.IP != "93.184.216.34" || res.Target != "example.test" || res.ID != "abcd1234" || res.V != 1 {
		t.Errorf("поля: %+v", res)
	}
	if res.Finished == 0 || res.Started == 0 {
		t.Errorf("started/finished: %d %d", res.Started, res.Finished)
	}
	for name, p := range map[string]*ComparePath{"direct": res.Paths.Direct, "vpn": res.Paths.VPN} {
		if !p.Available || p.FirstMS == nil || len(p.Samples) != 5 || nils(p.Samples) != 0 {
			t.Errorf("%s: %+v", name, p)
		}
	}
	// HEAD идут строго по очереди direct, vpn, direct, vpn, …
	got := strings.Join(log.snapshot(), ",")
	if want := strings.TrimSuffix(strings.Repeat("direct,vpn,", 5), ","); got != want {
		t.Errorf("порядок запросов:\n got %s\nwant %s", got, want)
	}
	// Прямой выход получил найденный адрес, VPN — домен как есть.
	if d := e.direct.destinations(); len(d) == 0 || d[0].Addr != netip.MustParseAddr("93.184.216.34") || d[0].Port != 443 || d[0].IsFqdn() {
		t.Errorf("direct dest: %v", d)
	}
	if d := e.vpn.destinations(); len(d) == 0 || d[0].Fqdn != "example.test" || d[0].Port != 443 {
		t.Errorf("vpn dest: %v", d)
	}
	// SNI = домен, по одному соединению на дорогу (keep-alive).
	if s, _ := ds.sni.Load().(string); s != "example.test" {
		t.Errorf("sni = %q", s)
	}
	if e.direct.dials.Load() != 1 || e.vpn.dials.Load() != 1 {
		t.Errorf("соединений: direct %d, vpn %d", e.direct.dials.Load(), e.vpn.dials.Load())
	}
}

func TestCompareTLSIPTargetNoSNI(t *testing.T) {
	e := newCmpEnv(t)
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, true)
	vs := newCmpServer(t, "vpn", log, true)
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)
	e.run.resolve = func(context.Context, string) (netip.Addr, error) {
		t.Error("IP не надо резолвить")
		return netip.Addr{}, errors.New("no")
	}
	res := e.measure(t, CompareRequest{Target: "203.0.113.7", Port: 8443, Count: 3})
	if res.Error != "" || res.Method != MethodTLS || res.IP != "203.0.113.7" {
		t.Fatalf("итог: %+v", res)
	}
	if s, _ := ds.sni.Load().(string); s != "" {
		t.Errorf("для IP SNI не нужен, а он %q", s)
	}
	if d := e.vpn.destinations(); len(d) == 0 || d[0].Addr != netip.MustParseAddr("203.0.113.7") || d[0].Port != 8443 {
		t.Errorf("vpn dest: %v", d)
	}
}

func TestCompareRewritesResultAtomically(t *testing.T) {
	e := newCmpEnv(t)
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, true)
	vs := newCmpServer(t, "vpn", log, true)
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)
	ds.slow = func(int) time.Duration { return 8 * time.Millisecond }
	vs.slow = ds.slow

	var (
		wg        sync.WaitGroup
		stop      atomic.Bool
		sawNot    atomic.Bool
		sawDone   atomic.Bool
		maxSample atomic.Int32
		broken    atomic.Value
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		path := compareResPath(e.dir, "abcd1234")
		for !stop.Load() {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var res CompareResult
			if err := json.Unmarshal(data, &res); err != nil {
				broken.Store(fmt.Sprintf("%v: %q", err, data))
				return
			}
			if res.Done {
				sawDone.Store(true)
			} else {
				sawNot.Store(true)
			}
			if n := int32(len(res.Paths.Direct.Samples)); n > maxSample.Load() {
				maxSample.Store(n)
			}
		}
	}()
	res := e.measure(t, CompareRequest{Target: "example.test", Count: 6})
	time.Sleep(20 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	if b := broken.Load(); b != nil {
		t.Fatalf("прочитан неполный файл: %v", b)
	}
	if !sawNot.Load() || !sawDone.Load() || !res.Done {
		t.Errorf("done:false видели %v, done:true %v", sawNot.Load(), sawDone.Load())
	}
	if maxSample.Load() < 2 {
		t.Errorf("промежуточных samples не было")
	}
	// Временных файлов не осталось.
	entries, _ := os.ReadDir(e.dir)
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".tmp") {
			t.Errorf("остался %s", en.Name())
		}
	}
}

func TestCompareTimeoutIsNull(t *testing.T) {
	e := newCmpEnv(t)
	e.run.timeout = 150 * time.Millisecond
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, true)
	vs := newCmpServer(t, "vpn", log, true)
	vs.slow = func(n int) time.Duration {
		if n == 0 { // первый HEAD «завис»
			return 400 * time.Millisecond
		}
		return 0
	}
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)
	res := e.measure(t, CompareRequest{Target: "example.test", Count: 4})
	if res.Error != "" || !res.Done {
		t.Fatalf("итог: %+v", res)
	}
	if v := res.Paths.VPN.Samples; len(v) != 4 || v[0] != nil || nils(v) != 1 {
		t.Errorf("vpn samples: %v", fmtSamples(v))
	}
	if nils(res.Paths.Direct.Samples) != 0 {
		t.Errorf("direct samples: %v", fmtSamples(res.Paths.Direct.Samples))
	}
	// null кодируется как null, а не как 0.
	raw, _ := os.ReadFile(compareResPath(e.dir, "abcd1234"))
	if !strings.Contains(string(raw), "null") {
		t.Errorf("в файле нет null: %s", raw)
	}
}

func TestCompareReconnectOnServerClose(t *testing.T) {
	e := newCmpEnv(t)
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, false) // сервер закрывает соединение после каждого ответа
	vs := newCmpServer(t, "vpn", log, false)
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)
	res := e.measure(t, CompareRequest{Target: "example.test", Count: 5})
	if res.Error != "" || res.Method != MethodTLS {
		t.Fatalf("итог: %+v", res)
	}
	for name, p := range map[string]*ComparePath{"direct": res.Paths.Direct, "vpn": res.Paths.VPN} {
		if nils(p.Samples) != 0 || len(p.Samples) != 5 || p.FirstMS == nil {
			t.Errorf("%s: переподключение посчитано неудачей: %v", name, fmtSamples(p.Samples))
		}
	}
	if e.direct.dials.Load() < 3 {
		t.Errorf("переподключений не было: %d соединений", e.direct.dials.Load())
	}
}

func TestCompareDirectBlockedStillTLS(t *testing.T) {
	// Напрямую TCP не открывается (заблокировано), через VPN всё работает: это сравнение,
	// а не icmp — прямая дорога просто вся в null.
	e := newCmpEnv(t)
	e.run.timeout = 100 * time.Millisecond
	log := &cmpLog{}
	vs := newCmpServer(t, "vpn", log, true)
	e.vpn.addr = hostPort(vs)
	res := e.measure(t, CompareRequest{Target: "example.test", Count: 3})
	if res.Method != MethodTLS || res.Error != "" {
		t.Fatalf("итог: %+v", res)
	}
	if res.Paths.Direct.FirstMS != nil || nils(res.Paths.Direct.Samples) != 3 {
		t.Errorf("direct: %+v", res.Paths.Direct)
	}
	if nils(res.Paths.VPN.Samples) != 0 || res.Paths.VPN.FirstMS == nil {
		t.Errorf("vpn: %+v", res.Paths.VPN)
	}
}

func TestCompareTCPOnlyWhenTLSFails(t *testing.T) {
	// Порт открыт, но TLS не отвечает: меряем открытие TCP напрямую, VPN сравнить нельзя.
	e := newCmpEnv(t)
	e.run.timeout = 150 * time.Millisecond
	e.direct.addr = newClosingListener(t)
	e.vpn.addr = e.direct.addr
	res := e.measure(t, CompareRequest{Target: "example.test", Count: 4})
	if res.Error != "" || !res.Done || res.Method != MethodTLS {
		t.Fatalf("итог: %+v", res)
	}
	if !res.Paths.Direct.Available || len(res.Paths.Direct.Samples) != 4 || nils(res.Paths.Direct.Samples) != 0 || res.Paths.Direct.FirstMS == nil {
		t.Errorf("direct: %+v", res.Paths.Direct)
	}
	if res.Paths.VPN.Available || res.Paths.VPN.Note == "" || len(res.Paths.VPN.Samples) != 0 {
		t.Errorf("vpn: %+v", res.Paths.VPN)
	}
}

// newClosingListener — TCP-порт открыт, но соединение сразу закрывается (TLS не выйдет).
func newClosingListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestCompareDirectTLSResetStillCompares(t *testing.T) {
	// Блокировка по SNI: напрямую TCP открывается, но рукопожатие сорвано; через VPN всё
	// работает. Это сравнение tls (прямая дорога вся в null), а не «только TCP».
	e := newCmpEnv(t)
	e.run.timeout = 150 * time.Millisecond
	e.direct.addr = newClosingListener(t)
	vs := newCmpServer(t, "vpn", &cmpLog{}, true)
	e.vpn.addr = hostPort(vs)
	res := e.measure(t, CompareRequest{Target: "example.test", Count: 3})
	if res.Method != MethodTLS || res.Error != "" {
		t.Fatalf("итог: %+v", res)
	}
	d, v := res.Paths.Direct, res.Paths.VPN
	if !d.Available || d.FirstMS != nil || len(d.Samples) != 3 || nils(d.Samples) != 3 || d.Note != "" {
		t.Errorf("direct: %+v %s", d, fmtSamples(d.Samples))
	}
	if !v.Available || v.FirstMS == nil || nils(v.Samples) != 0 || len(v.Samples) != 3 {
		t.Errorf("vpn: %+v %s", v, fmtSamples(v.Samples))
	}
}

// --- icmp ---

func TestCompareICMPFallback(t *testing.T) {
	e := newCmpEnv(t) // оба выхода отказывают: TCP на порт не открывается нигде
	e.run.timeout = 100 * time.Millisecond
	res := e.measure(t, CompareRequest{Target: "game.example.test", Port: 27015, Count: 4})
	if res.Error != "" || !res.Done || res.Method != MethodICMP {
		t.Fatalf("итог: %+v", res)
	}
	d, v := res.Paths.Direct, res.Paths.VPN
	if !d.Available || len(d.Samples) != 4 || d.Samples[0] == nil || *d.Samples[0] != 21 || *d.Samples[3] != 24 || d.FirstMS != nil {
		t.Errorf("direct: %+v %s", d, fmtSamples(d.Samples))
	}
	if v.Available || !v.Estimate || v.Note != "через VPN измерить нельзя: сервер отвечает только на игровые пакеты" {
		t.Errorf("vpn: %+v", v)
	}
	if len(v.Samples) != 4 || v.Samples[0] == nil || *v.Samples[0] != 11 || v.FirstMS != nil {
		t.Errorf("vpn samples: %s", fmtSamples(v.Samples))
	}
	if res.IP != "93.184.216.34" {
		t.Errorf("ip = %q", res.IP)
	}
}

func TestCompareICMPNoPermissionIsHonest(t *testing.T) {
	e := newCmpEnv(t)
	e.run.timeout = 100 * time.Millisecond
	e.run.ping = func(context.Context, netip.Addr, time.Duration) (time.Duration, error) {
		return 0, errICMPNoPermission
	}
	res := e.measure(t, CompareRequest{Target: "game.example.test", Port: 27015, Count: 3})
	if res.Method != MethodICMP || res.Error != "" || !res.Done {
		t.Fatalf("итог: %+v", res)
	}
	if res.Paths.Direct.Available || res.Paths.Direct.Note == "" || len(res.Paths.Direct.Samples) != 0 {
		t.Errorf("direct: %+v", res.Paths.Direct)
	}
	if !res.Paths.VPN.Estimate || len(res.Paths.VPN.Samples) != 3 {
		t.Errorf("vpn: %+v", res.Paths.VPN)
	}
}

func TestCompareICMPTimeouts(t *testing.T) {
	e := newCmpEnv(t)
	e.run.timeout = 100 * time.Millisecond
	e.run.ping = func(context.Context, netip.Addr, time.Duration) (time.Duration, error) {
		return 0, errors.New("таймаут")
	}
	res := e.measure(t, CompareRequest{Target: "game.example.test", Port: 27015, Count: 3})
	if nils(res.Paths.Direct.Samples) != 3 || !res.Paths.Direct.Available || res.Paths.Direct.Note == "" {
		t.Errorf("direct: %+v", res.Paths.Direct)
	}
}

// --- ошибки запроса ---

func TestCompareErrors(t *testing.T) {
	e := newCmpEnv(t)

	// Домен не резолвится.
	e.run.resolve = func(context.Context, string) (netip.Addr, error) { return netip.Addr{}, errors.New("no such host") }
	res := e.measure(t, CompareRequest{ID: "aaaaaaa1", Target: "nope.example.test"})
	if !res.Done || !strings.Contains(res.Error, "nope.example.test") || res.Paths.Direct == nil || res.Paths.VPN == nil {
		t.Errorf("резолв: %+v", res)
	}

	// Повреждённый запрос.
	if err := os.WriteFile(compareReqPath(e.dir, "aaaaaaa2"), []byte("{{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.run.process("aaaaaaa2")
	res = e.readResult(t, "aaaaaaa2")
	if !res.Done || res.Error == "" || res.ID != "aaaaaaa2" {
		t.Errorf("повреждённый: %+v", res)
	}

	// Неверное содержание.
	res = e.measure(t, CompareRequest{ID: "aaaaaaa3", Target: "https://x.test/path"})
	if !res.Done || res.Error == "" {
		t.Errorf("неверная цель: %+v", res)
	}
}

// --- очередь ---

func TestCompareQueueLimit(t *testing.T) {
	e := newCmpEnv(t)
	base := time.Now().Add(-time.Minute)
	for i := 0; i < 35; i++ {
		id := fmt.Sprintf("q%07d", i)
		e.request(t, CompareRequest{ID: id, Target: "example.test"})
		mt := base.Add(time.Duration(i) * time.Second)
		_ = os.Chtimes(compareReqPath(e.dir, id), mt, mt)
	}
	// Уже отвеченный запрос в очередь не идёт.
	e.request(t, CompareRequest{ID: "answered1", Target: "example.test"})
	_ = os.WriteFile(compareResPath(e.dir, "answered1"), []byte(`{"v":1,"done":true}`), 0o644)

	e.run.scan()
	e.run.access.Lock()
	queue := append([]queued(nil), e.run.queue...)
	e.run.access.Unlock()
	if len(queue) != 30 {
		t.Fatalf("в очереди %d, ждали 30", len(queue))
	}
	if queue[0].id != "q0000000" || queue[29].id != "q0000029" {
		t.Errorf("порядок очереди: %s … %s", queue[0].id, queue[29].id)
	}
	for i := 30; i < 35; i++ {
		res := e.readResult(t, fmt.Sprintf("q%07d", i))
		if !res.Done || res.Error != "слишком много запросов" {
			t.Errorf("лишний %d: %+v", i, res)
		}
	}
	if _, err := os.Stat(compareResPath(e.dir, "q0000000")); err == nil {
		t.Error("поставленный в очередь уже с res")
	}
	// Повторный скан ничего не меняет.
	e.run.scan()
	e.run.access.Lock()
	n := len(e.run.queue)
	e.run.access.Unlock()
	if n != 30 {
		t.Errorf("после повторного скана %d", n)
	}
}

func (e *cmpEnv) startLoops() {
	e.run.started = true
	e.run.wg.Add(2)
	go e.run.scanLoop()
	go e.run.workLoop()
}

func TestCompareRunsOneAtATimeEndToEnd(t *testing.T) {
	e := newCmpEnv(t)
	e.run.pause = 2 * time.Millisecond
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, true)
	vs := newCmpServer(t, "vpn", log, true)
	ds.slow = func(int) time.Duration { return 3 * time.Millisecond }
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)
	ids := []string{"e2e00001", "e2e00002", "e2e00003"}
	for _, id := range ids {
		e.request(t, CompareRequest{ID: id, Target: "example.test", Count: 3})
	}
	e.startLoops()
	deadline := time.Now().Add(10 * time.Second)
	for _, id := range ids {
		for {
			data, err := os.ReadFile(compareResPath(e.dir, id))
			var res CompareResult
			if err == nil && json.Unmarshal(data, &res) == nil && res.Done {
				if res.Error != "" || len(res.Paths.Direct.Samples) != 3 {
					t.Errorf("%s: %+v", id, res)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: результата нет", id)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	e.run.stop()
	if m := log.maxInfl.Load(); m != 1 {
		t.Errorf("параллельных замеров: %d", m)
	}
	// Три запроса по очереди: каждый даёт 3+3 HEAD.
	if n := len(log.snapshot()); n != 18 {
		t.Errorf("HEAD всего %d, ждали 18", n)
	}
}

func TestCompareStopMidMeasure(t *testing.T) {
	e := newCmpEnv(t)
	e.run.pause = 20 * time.Millisecond
	log := &cmpLog{}
	ds := newCmpServer(t, "direct", log, true)
	vs := newCmpServer(t, "vpn", log, true)
	e.direct.addr, e.vpn.addr = hostPort(ds), hostPort(vs)
	e.request(t, CompareRequest{ID: "stop0001", Target: "example.test", Count: 30})
	e.request(t, CompareRequest{ID: "stop0002", Target: "example.test", Count: 30})
	e.startLoops()
	deadline := time.Now().Add(5 * time.Second)
	for len(log.snapshot()) < 4 {
		if time.Now().After(deadline) {
			t.Fatal("замер не начался")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.run.stop()
	for _, id := range []string{"stop0001", "stop0002"} {
		res := e.readResult(t, id)
		if !res.Done || res.Error != "ядро остановлено" {
			t.Errorf("%s: done=%v error=%q", id, res.Done, res.Error)
		}
	}
}

// --- очистка ---

func TestCompareCleanup(t *testing.T) {
	dir := cmpTempDir(t)
	now := time.Now()
	write := func(name, body string, age time.Duration) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		mt := now.Add(-age)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	write("req-old00001.json", "{}", 2*time.Hour)
	write("res-old00001.json", `{"done":true}`, 2*time.Hour)
	write("res-old00002.json.tmp", "{", 2*time.Hour)
	write("req-new00001.json", "{}", 10*time.Minute)
	write("res-new00001.json", `{"v":1,"id":"new00001","done":true}`, 10*time.Minute)
	write("res-hung0001.json", `{"v":1,"id":"hung0001","done":false,"paths":{}}`, 10*time.Minute)
	write("notes.txt", "чужой файл", 5*time.Hour)

	cleanupCompareDir(dir, now)

	for _, gone := range []string{"req-old00001.json", "res-old00001.json", "res-old00002.json.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); err == nil {
			t.Errorf("%s не удалён", gone)
		}
	}
	for _, kept := range []string{"req-new00001.json", "res-new00001.json", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("%s удалён зря", kept)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "res-hung0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res CompareResult
	if err := json.Unmarshal(data, &res); err != nil || !res.Done || res.Error == "" || res.Paths.Direct == nil || res.Paths.VPN == nil {
		t.Errorf("зависший res не закрыт: %s", data)
	}
}

// --- служба ---

func TestNewComparerOnlyWithDir(t *testing.T) {
	if NewComparer(CompareOptions{}) != nil {
		t.Error("служба без папки")
	}
	c := NewComparer(CompareOptions{Dir: t.TempDir()})
	if c == nil || c.Name() == "" {
		t.Fatal("нет службы с папкой")
	}
	// Без привязки к службе ядра ничего не запускается и не падает.
	if err := c.Close(); err != nil {
		t.Error(err)
	}
}

func TestSystemPingLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := systemPing(ctx, netip.MustParseAddr("127.0.0.1"), 2*time.Second)
	if errors.Is(err, errICMPNoPermission) {
		t.Skip("нет прав на ICMP")
	}
	if err != nil {
		t.Skipf("ICMP на этой машине недоступен: %v", err)
	}
	if d <= 0 || d > 2*time.Second {
		t.Errorf("rtt = %v", d)
	}
}

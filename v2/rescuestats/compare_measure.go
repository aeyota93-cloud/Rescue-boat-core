package rescuestats

// Замеры «Сравнить пути»: порядок раундов, tls-метод (рукопожатие + HEAD по keep-alive),
// запасной icmp-метод и запись промежуточных результатов.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	MethodTLS  = "tls"
	MethodICMP = "icmp"

	noteNoVPN        = "VPN не подключён"
	noteNoDirect     = "прямой выход недоступен"
	noteICMPVPN      = "через VPN измерить нельзя: сервер отвечает только на игровые пакеты"
	noteTCPOnlyVPN   = "через VPN сравнить нельзя: сервер не завершает защищённое соединение (TLS), а время подключения к VPN-серверу не показывает путь до цели"
	noteTCPOnlyDir   = "защищённое соединение не установилось, меряем только открытие TCP-соединения"
	noteNoICMPRights = "для проверки ping не хватает прав (нужен запуск от администратора)"
)

// resolveFunc — прямой DNS: адрес цели для показа и для ICMP.
type resolveFunc func(ctx context.Context, host string) (netip.Addr, error)

// systemResolve — запасной резолвер: системный (когда у ядра нет прямого DNS-сервера).
func systemResolve(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	return pickAddr(addrs)
}

// newCoreResolver — через DNS ядра с сервером «напрямую» (tag), в обход правил DNS и
// поддельных адресов; если сервера нет — системный резолвер.
func newCoreResolver(coreCtx context.Context, directTag string) resolveFunc {
	if coreCtx == nil || directTag == "" {
		return systemResolve
	}
	router := service.FromContext[adapter.DNSRouter](coreCtx)
	transports := service.FromContext[adapter.DNSTransportManager](coreCtx)
	if router == nil || transports == nil {
		return systemResolve
	}
	return func(ctx context.Context, host string) (netip.Addr, error) {
		transport, ok := transports.Transport(directTag)
		if !ok {
			return systemResolve(ctx, host)
		}
		addrs, err := router.Lookup(ctx, host, adapter.DNSQueryOptions{Transport: transport})
		if err != nil {
			return netip.Addr{}, err
		}
		return pickAddr(addrs)
	}
}

// pickAddr — предпочитаем IPv4 (ICMP и TCP по нему надёжнее), иначе первый IPv6.
func pickAddr(addrs []netip.Addr) (netip.Addr, error) {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return netip.Addr{}, errors.New("адрес не найден")
}

// pathState — одна дорога в замере.
type pathState struct {
	name   string
	proxy  bool // выход VPN (select или отдельный сервер): домен резолвит сам выход
	dialer N.Dialer
	out    *ComparePath

	conn   net.Conn // живое TLS-соединение для замеров keep-alive
	br     *bufio.Reader
	cancel context.CancelFunc // контекст, с которым открыто conn (см. connect)
}

type compareMeasure struct {
	r       *compareRun
	req     *CompareRequest
	res     *CompareResult
	direct  *pathState
	vpn     *pathState
	servers []*pathState // по порядку select
	host    string       // для заголовка Host
	sni     string
	addr    netip.Addr
}

func newCompareMeasure(r *compareRun, req *CompareRequest) *compareMeasure {
	res := newCompareResult(req.ID, r.now())
	res.Target = req.Target
	m := &compareMeasure{r: r, req: req, res: res}
	m.direct = &pathState{name: "direct", out: res.Paths.Direct}
	m.vpn = &pathState{name: "vpn", proxy: true, out: res.Paths.VPN}
	if d := r.directDialer(); d != nil {
		m.direct.dialer = d
	}
	if d := r.vpnDialer(); d != nil {
		m.vpn.dialer = d
	}
	for _, s := range r.serverDialers() {
		out := &CompareServerPath{Tag: s.tag, ComparePath: *newComparePath()}
		res.Paths.Servers = append(res.Paths.Servers, out)
		m.servers = append(m.servers, &pathState{name: s.tag, proxy: true, dialer: s.dialer, out: &out.ComparePath})
	}
	if ip, err := netip.ParseAddr(req.Target); err == nil {
		m.addr = ip
		m.host = req.Target
		if ip.Is6() {
			m.host = "[" + req.Target + "]"
		}
	} else {
		m.host = req.Target
		m.sni = req.Target
	}
	if req.Port != 443 && req.Port != 80 {
		m.host += ":" + strconv.Itoa(req.Port)
	}
	return m
}

// proxies — дороги через VPN: vpn, потом серверы по порядку.
func (m *compareMeasure) proxies() []*pathState {
	return append([]*pathState{m.vpn}, m.servers...)
}

// all — все дороги в порядке круга: direct, vpn, сервер 1, сервер 2, …
func (m *compareMeasure) all() []*pathState {
	return append([]*pathState{m.direct}, m.proxies()...)
}

func (m *compareMeasure) publish() {
	_ = writeCompareResult(m.r.dir, m.res)
}

func (m *compareMeasure) finish(errText string) {
	for _, p := range m.all() {
		p.close()
	}
	m.res.Done = true
	m.res.Finished = m.r.now().UnixMilli()
	if errText != "" {
		m.res.Error = errText
	}
	m.publish()
}

func (m *compareMeasure) run() {
	ctx := m.r.ctx
	m.publish() // приложение видит, что запрос взят в работу

	if !m.addr.IsValid() {
		rctx, cancel := context.WithTimeout(ctx, compareResolveTO)
		ip, err := m.r.resolve(rctx, m.req.Target)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				m.finish("ядро остановлено")
			} else {
				m.finish("не удалось найти адрес «" + m.req.Target + "»: " + err.Error())
			}
			return
		}
		m.addr = ip
	}
	m.res.IP = m.addr.String()
	m.publish()

	m.direct.out.Available = m.direct.dialer != nil
	if m.direct.dialer == nil {
		m.direct.out.Note = noteNoDirect
	}
	for _, p := range m.proxies() {
		p.out.Available = p.dialer != nil
		if p.dialer == nil {
			p.out.Note = noteNoVPN
		}
	}

	method := m.chooseAndFirst(ctx)
	if ctx.Err() != nil {
		m.finish("ядро остановлено")
		return
	}
	switch method {
	case MethodICMP:
		m.runICMP(ctx)
	case "tcp":
		m.runTCPOnly(ctx)
	default:
		m.runTLS(ctx)
	}
	if ctx.Err() != nil {
		m.finish("ядро остановлено")
		return
	}
	m.finish("")
}

// firstResult — итог первого соединения по дороге.
type firstResult struct {
	tcpOpened bool          // TCP-соединение открылось
	tcpTime   time.Duration // время до открытия TCP
	tlsOK     bool
	total     time.Duration // до завершённого рукопожатия
}

// chooseAndFirst делает первое соединение по всем дорогам (direct, vpn, серверы) и выбирает метод:
//
//   - TLS прошёл напрямую — tls;
//   - напрямую TLS не прошёл (TCP закрыт или рукопожатие сорвано, как при блокировке по SNI),
//     а через VPN или какой-то сервер прошёл — tls: прямая дорога просто вся в null;
//   - TLS не вышел нигде, но напрямую TCP открылся — tcp (меряем только открытие соединения);
//   - TCP не вышел ни там, ни там — icmp.
//
// Через VPN судим только по рукопожатию: открытие TCP у прокси-выхода к цели отношения не имеет.
func (m *compareMeasure) chooseAndFirst(ctx context.Context) string {
	var d firstResult
	if m.direct.dialer != nil {
		d = m.connectFirst(ctx, m.direct)
		m.publish()
	}
	proxyTLS := false
	for _, p := range m.proxies() {
		if ctx.Err() != nil {
			return MethodTLS
		}
		if p.dialer != nil {
			proxyTLS = m.connectFirst(ctx, p).tlsOK || proxyTLS
			m.publish()
		}
	}
	switch {
	case d.tlsOK, proxyTLS:
		m.res.Method = MethodTLS
	case d.tcpOpened:
		m.res.Method = MethodTLS
		m.direct.out.Note = noteTCPOnlyDir
		first := msOf(d.tcpTime)
		m.direct.out.FirstMS = &first
		for _, p := range m.proxies() {
			p.out.Available = false
			p.out.FirstMS = nil
			p.out.Note = noteTCPOnlyVPN
		}
		m.publish()
		return "tcp"
	default:
		m.res.Method = MethodICMP
		m.direct.out.FirstMS = nil
		for _, p := range m.proxies() {
			p.out.FirstMS = nil
			p.out.Available = false
			p.out.Estimate = true
			p.out.Note = noteICMPVPN
		}
		m.publish()
		return MethodICMP
	}
	m.publish()
	return MethodTLS
}

// connectFirst — новое соединение + рукопожатие; first_ms пишется только при успехе.
func (m *compareMeasure) connectFirst(ctx context.Context, p *pathState) firstResult {
	p.close()
	res := m.connect(ctx, p)
	if res.tlsOK {
		first := msOf(res.total)
		p.out.FirstMS = &first
	}
	return res
}

// connect: dial → TLS-рукопожатие, всё в пределах таймаута замера. Соединение остаётся в p.
// Контекст соединения живёт, пока живо само соединение: XHTTP привязывает соединение к
// контексту набора, и отмена сразу после рукопожатия рвала его — через запасной XHTTP все
// замеры выходили «не ответил». Таймаут — таймером, который снимается после рукопожатия.
func (m *compareMeasure) connect(ctx context.Context, p *pathState) (res firstResult) {
	cctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(m.r.timeout, cancel)
	ok := false
	defer func() {
		if !ok {
			timer.Stop()
			cancel()
		}
	}()
	start := time.Now()
	conn, err := p.dialer.DialContext(cctx, N.NetworkTCP, m.destination(p))
	if err != nil {
		return
	}
	res.tcpOpened = true
	res.tcpTime = time.Since(start)
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // меряем время, не доверие
		ServerName:         m.sni,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(cctx); err != nil {
		_ = conn.Close()
		return
	}
	res.total = time.Since(start)
	if !timer.Stop() { // таймаут сработал на последнем шаге — контекст уже отменён
		_ = conn.Close()
		return
	}
	ok = true
	res.tlsOK = true
	p.conn, p.cancel = tlsConn, cancel
	p.br = bufio.NewReader(tlsConn)
	return
}

// destination: напрямую — уже найденный адрес (DNS в замер не входит); через VPN и серверы —
// домен как есть, его резолвит сам выход.
func (m *compareMeasure) destination(p *pathState) M.Socksaddr {
	port := uint16(m.req.Port)
	if p.proxy && m.sni != "" {
		return M.Socksaddr{Fqdn: m.req.Target, Port: port}
	}
	return M.Socksaddr{Addr: m.addr, Port: port}
}

// --- tls ---

func (m *compareMeasure) runTLS(ctx context.Context) {
	for i := 0; i < m.req.Count; i++ {
		for _, p := range m.all() {
			if ctx.Err() != nil {
				return
			}
			if p.dialer == nil {
				p.out.Samples = append(p.out.Samples, nil)
				continue
			}
			p.out.Samples = append(p.out.Samples, m.sample(ctx, p))
			m.publish()
			if !m.sleep(ctx) {
				return
			}
		}
	}
}

// sample — задержка запрос→ответ на открытом соединении. Закрытое сервером соединение
// открываем заново (это не неудача); таймаут или обрыв на свежем соединении — null.
func (m *compareMeasure) sample(ctx context.Context, p *pathState) *int {
	for attempt := 0; attempt < 2; attempt++ {
		reused := p.conn != nil
		if !reused {
			if res := m.connect(ctx, p); !res.tlsOK {
				return nil
			}
		}
		d, err := m.headRoundTrip(ctx, p)
		if err == nil {
			ms := msOf(d)
			return &ms
		}
		p.close()
		if reused && !isTimeout(err) && ctx.Err() == nil {
			continue
		}
		return nil
	}
	return nil
}

// headRoundTrip шлёт HEAD / и меряет время до первой строки ответа; остаток заголовков
// дочитывается, чтобы следующий замер начался с чистого соединения.
func (m *compareMeasure) headRoundTrip(ctx context.Context, p *pathState) (time.Duration, error) {
	deadline := time.Now().Add(m.r.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = p.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = p.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	// У XHTTP SetDeadline ничего не делает: зависший ответ прерываем закрытием соединения.
	conn := p.conn
	var timedOut atomic.Bool
	guard := time.AfterFunc(time.Until(deadline), func() {
		timedOut.Store(true)
		_ = conn.Close()
	})
	defer guard.Stop()
	wrap := func(err error) error {
		if timedOut.Load() {
			return os.ErrDeadlineExceeded
		}
		return err
	}

	request := "HEAD / HTTP/1.1\r\nHost: " + m.host + "\r\nUser-Agent: prichal-compare\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
	start := time.Now()
	if _, err := io.WriteString(p.conn, request); err != nil {
		return 0, wrap(err)
	}
	// Время — до первого байта ответа: так же меряется и сервер, отвечающий не по HTTP.
	if _, err := p.br.Peek(1); err != nil {
		return 0, wrap(err)
	}
	elapsed := time.Since(start)
	n := p.br.Buffered()
	if n > 5 {
		n = 5
	}
	if head, _ := p.br.Peek(n); !strings.HasPrefix("HTTP/", string(head)) {
		p.close() // ответ есть, но не HTTP: следующий замер — на новом соединении
		return elapsed, nil
	}
	for {
		l, err := p.br.ReadString('\n')
		if err != nil {
			p.close() // замер уже есть, но соединение неполное
			return elapsed, nil
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	return elapsed, nil
}

// --- только TCP ---

// runTCPOnly: TLS не вышел, но TCP открыт — меряем время открытия TCP напрямую.
func (m *compareMeasure) runTCPOnly(ctx context.Context) {
	for i := 0; i < m.req.Count; i++ {
		if ctx.Err() != nil {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, m.r.timeout)
		start := time.Now()
		conn, err := m.direct.dialer.DialContext(cctx, N.NetworkTCP, m.destination(m.direct))
		cancel()
		if err != nil {
			m.direct.out.Samples = append(m.direct.out.Samples, nil)
		} else {
			ms := msOf(time.Since(start))
			_ = conn.Close()
			m.direct.out.Samples = append(m.direct.out.Samples, &ms)
		}
		m.publish()
		if !m.sleep(ctx) {
			return
		}
	}
}

// --- icmp ---

// runICMP: direct — ping цели, vpn и серверы — оценка качества туннеля (connection-test-url
// через этот выход).
func (m *compareMeasure) runICMP(ctx context.Context) {
	link := m.r.opts.TestURL
	if link == "" {
		link = defaultProbeURL
	}
	pingOK := m.direct.dialer != nil
	for i := 0; i < m.req.Count; i++ {
		if ctx.Err() != nil {
			return
		}
		if pingOK {
			pctx, cancel := context.WithTimeout(ctx, m.r.timeout)
			d, err := m.r.ping(pctx, m.addr, m.r.timeout)
			cancel()
			switch {
			case errors.Is(err, errICMPNoPermission):
				pingOK = false
				m.direct.out.Available = false
				m.direct.out.Samples = []*int{}
				m.direct.out.Note = noteNoICMPRights
			case err != nil || d <= 0 || d > m.r.timeout:
				m.direct.out.Samples = append(m.direct.out.Samples, nil)
			default:
				ms := msOf(d)
				m.direct.out.Samples = append(m.direct.out.Samples, &ms)
			}
			m.publish()
			if !m.sleep(ctx) {
				return
			}
		}
		for _, p := range m.proxies() {
			if p.dialer == nil {
				continue
			}
			p.out.Samples = append(p.out.Samples, m.urlTestSample(ctx, link, p))
			m.publish()
			if !m.sleep(ctx) {
				return
			}
		}
	}
	if pingOK && allNil(m.direct.out.Samples) {
		m.direct.out.Note = "цель не отвечает на ping"
	}
}

func (m *compareMeasure) urlTestSample(ctx context.Context, link string, p *pathState) *int {
	tctx, cancel := context.WithTimeout(ctx, m.r.timeout)
	defer cancel()
	d, err := m.r.urlTest(tctx, link, p.dialer)
	if err != nil || d <= 0 || d > m.r.timeout {
		return nil
	}
	ms := msOf(d)
	return &ms
}

// --- общее ---

func (m *compareMeasure) sleep(ctx context.Context) bool {
	if m.r.pause <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(m.r.pause)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *pathState) close() {
	if p.conn != nil {
		_ = p.conn.Close()
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.conn, p.br, p.cancel = nil, nil, nil
}

func msOf(d time.Duration) int {
	ms := int(d / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	return ms
}

func allNil(s []*int) bool {
	for _, v := range s {
		if v != nil {
			return false
		}
	}
	return true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

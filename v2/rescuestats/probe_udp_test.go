package rescuestats

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

type udpTestPacket struct {
	data   []byte
	source net.Addr
}

type udpTestConn struct {
	packets    chan udpTestPacket
	closed     chan struct{}
	written    chan struct{}
	once       sync.Once
	deadline   time.Time
	noDeadline bool // SetDeadline возвращает ошибку, как у пакетных соединений hysteria2/vless
	readErr    error
	respond    func(*dns.Msg, M.Socksaddr) []udpTestPacket
}

func newUDPTestConn() *udpTestConn {
	return &udpTestConn{packets: make(chan udpTestPacket, 8), closed: make(chan struct{}), written: make(chan struct{})}
}

func (c *udpTestConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.packets:
		return copy(b, p.data), p.source, nil
	default:
	}
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	select {
	case p := <-c.packets:
		return copy(b, p.data), p.source, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *udpTestConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Требуем Socksaddr: так адрес получает Hysteria2.
	dst, ok := addr.(M.Socksaddr)
	if !ok {
		return 0, errors.New("нужен Socksaddr")
	}
	var query dns.Msg
	if err := query.Unpack(b); err != nil {
		return 0, err
	}
	if c.respond != nil {
		for _, p := range c.respond(&query, dst) {
			c.packets <- p
		}
	}
	close(c.written)
	return len(b), nil
}

func (c *udpTestConn) Close() error        { c.once.Do(func() { close(c.closed) }); return nil }
func (c *udpTestConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *udpTestConn) SetDeadline(t time.Time) error {
	if c.noDeadline {
		return os.ErrInvalid
	}
	c.deadline = t
	return nil
}
func (c *udpTestConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *udpTestConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

type udpTestDialer struct {
	conns map[M.Socksaddr]*udpTestConn
}

type udpBlockedDialer struct {
	udpTestDialer
	started chan struct{}
	release chan struct{}
}

func (d udpBlockedDialer) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	close(d.started)
	<-d.release
	return d.udpTestDialer.ListenPacket(ctx, dst)
}

func TestProbeUDPCanceledDuringListenClosesBeforeUse(t *testing.T) {
	dst := M.ParseSocksaddrHostPort("1.1.1.1", 53)
	conn := newUDPTestConn()
	dialer := udpBlockedDialer{udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: conn}}, make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- probeUDPTarget(ctx, dialer, dst, nil, nil) }()
	<-dialer.started
	cancel()
	close(dialer.release)
	if <-done {
		t.Fatal("отменённая проба успешна")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("позднее соединение не закрыто")
	}
	if !conn.deadline.IsZero() {
		t.Fatal("соединение использовано после отмены")
	}
	select {
	case <-conn.written:
		t.Fatal("данные отправлены после отмены")
	default:
	}
}

func (d udpTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("TCP не используется")
}
func (d udpTestDialer) ListenPacket(_ context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if c := d.conns[dst]; c != nil {
		return c, nil
	}
	return nil, errors.New("неизвестная цель")
}

func udpAnswer(query *dns.Msg, dst M.Socksaddr, mutate func(*dns.Msg)) udpTestPacket {
	var answer dns.Msg
	answer.SetReply(query)
	if mutate != nil {
		mutate(&answer)
	}
	wire, err := answer.Pack()
	if err != nil {
		panic(err)
	}
	// Другой тип адреса с тем же значением должен пройти проверку.
	return udpTestPacket{wire, dst.UDPAddr()}
}

func TestProbeUDPResponses(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		mutate                                       func(*dns.Msg)
		foreignSource, junkFirst, validAfter, wantOK bool
	}{
		{name: "верный", wantOK: true},
		{name: "NXDOMAIN", mutate: func(m *dns.Msg) { m.Rcode = dns.RcodeNameError }, wantOK: true},
		{name: "чужой ID", mutate: func(m *dns.Msg) { m.Id++ }},
		{name: "чужой источник", foreignSource: true},
		{name: "SERVFAIL", mutate: func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }},
		{name: "TC", mutate: func(m *dns.Msg) { m.Truncated = true }},
		{name: "QR", mutate: func(m *dns.Msg) { m.Response = false }},
		{name: "чужой вопрос", mutate: func(m *dns.Msg) { m.Question[0].Name = "example.org." }},
		{name: "чужой тип", mutate: func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }},
		{name: "чужой класс", mutate: func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }},
		{name: "нет вопроса", mutate: func(m *dns.Msg) { m.Question = nil }},
		{name: "мусор затем ответ", junkFirst: true, wantOK: true},
		{name: "чужой ID затем ответ", mutate: func(m *dns.Msg) { m.Id++ }, validAfter: true, wantOK: true},
		{name: "чужой источник затем ответ", foreignSource: true, validAfter: true, wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := M.ParseSocksaddrHostPort("1.1.1.1", 53)
			c := newUDPTestConn()
			c.readErr = os.ErrDeadlineExceeded
			c.respond = func(q *dns.Msg, dst M.Socksaddr) []udpTestPacket {
				p := udpAnswer(q, dst, tc.mutate)
				if tc.foreignSource {
					p.source = M.ParseSocksaddrHostPort("9.9.9.9", 53)
				}
				packets := []udpTestPacket{p}
				if tc.junkFirst {
					packets = append([]udpTestPacket{{[]byte{0, 1, 2}, dst}}, packets...)
				}
				if tc.validAfter {
					packets = append(packets, udpAnswer(q, dst, nil))
				}
				return packets
			}
			err := probeUDPTargetsWithTimeout(context.Background(), udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst}, udpTestTimeout)
			if (err == nil) != tc.wantOK {
				t.Fatalf("ошибка: %v, успех: %v", err, tc.wantOK)
			}
			select {
			case <-c.closed:
			default:
				t.Fatal("соединение не закрыто")
			}
		})
	}
}

// Живой тест 08.11 на всех 4 выходах: SetDeadline у них не поддержан, проба не должна сдаваться.
func TestProbeUDPDeadlineUnsupported(t *testing.T) {
	dst := M.ParseSocksaddrHostPort("1.1.1.1", 53)
	c := newUDPTestConn()
	c.noDeadline = true
	c.respond = func(q *dns.Msg, dst M.Socksaddr) []udpTestPacket { return []udpTestPacket{udpAnswer(q, dst, nil)} }
	if err := probeUDPTargetsWithTimeout(context.Background(), udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst}, udpTestTimeout); err != nil {
		t.Fatalf("без поддержки deadline: %v", err)
	}
}

func udpTestTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	return &failoverTestDeadline{Context: ctx, deadline: newFailoverClock().now().Add(d), duration: d, cancel: cancel}, cancel
}

func TestProbeUDPTimeout(t *testing.T) {
	for _, noDeadline := range []bool{false, true} {
		t.Run(fmt.Sprint(noDeadline), func(t *testing.T) {
			dst := M.ParseSocksaddrHostPort("1.1.1.1", 53)
			c := newUDPTestConn()
			c.noDeadline = noDeadline
			timeouts := make(chan *failoverTestDeadline, 1)
			timeout := func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
				ctx, cancel := udpTestTimeout(parent, d)
				timeouts <- ctx.(*failoverTestDeadline)
				return ctx, cancel
			}
			done := make(chan error, 1)
			go func() {
				done <- probeUDPTargetsWithTimeout(context.Background(), udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst}, timeout)
			}()
			deadline := <-timeouts
			<-c.written
			if deadline.duration != 4*time.Second {
				t.Fatal("тайм-аут UDP", deadline.duration)
			}
			deadline.expire()
			if err := <-done; err == nil {
				t.Fatal("ожидалась ошибка")
			}
			select {
			case <-c.closed:
			default:
				t.Fatal("соединение не закрыто по сроку")
			}
		})
	}
}

func TestProbeUDPParallel(t *testing.T) {
	first, second := M.ParseSocksaddrHostPort("1.1.1.1", 53), M.ParseSocksaddrHostPort("8.8.8.8", 53)
	silent, good := newUDPTestConn(), newUDPTestConn()
	good.respond = func(q *dns.Msg, dst M.Socksaddr) []udpTestPacket {
		// Вторая цель отвечает, только когда первая уже ждёт ответа.
		<-silent.written
		return []udpTestPacket{udpAnswer(q, dst, nil)}
	}
	if err := probeUDPTargetsWithTimeout(context.Background(), udpTestDialer{map[M.Socksaddr]*udpTestConn{first: silent, second: good}}, []M.Socksaddr{first, second}, udpTestTimeout); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*udpTestConn{silent, good} {
		select {
		case <-c.closed:
		default:
			t.Fatal("соединение не закрыто")
		}
	}
}

func TestProbeUDPCancel(t *testing.T) {
	dst := M.ParseSocksaddrHostPort("1.1.1.1", 53)
	c := newUDPTestConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- probeUDPTargetsWithTimeout(ctx, udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst}, udpTestTimeout)
	}()
	<-c.written
	cancel()
	if err := <-result; err != ctx.Err() {
		t.Fatalf("получено %v, ожидалось %v", err, ctx.Err())
	}
	select {
	case <-c.closed:
	default:
		t.Fatal("отмена не закрыла соединение")
	}
}

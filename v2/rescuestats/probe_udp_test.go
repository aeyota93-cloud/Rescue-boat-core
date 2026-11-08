package rescuestats

import (
	"context"
	"errors"
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
	packets        chan udpTestPacket
	closed         chan struct{}
	written        chan struct{}
	once           sync.Once
	deadline       time.Time
	ignoreDeadline bool
	noDeadline     bool // SetDeadline возвращает ошибку, как у пакетных соединений hysteria2/vless
	respond        func(*dns.Msg, M.Socksaddr) []udpTestPacket
}

func newUDPTestConn() *udpTestConn {
	return &udpTestConn{packets: make(chan udpTestPacket, 8), closed: make(chan struct{}), written: make(chan struct{})}
}

func (c *udpTestConn) ReadFrom(b []byte) (int, net.Addr, error) {
	var timer <-chan time.Time
	if !c.ignoreDeadline {
		t := time.NewTimer(time.Until(c.deadline))
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-c.packets:
		return copy(b, p.data), p.source, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, os.ErrDeadlineExceeded
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
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			err := probeUDPTargets(ctx, udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst})
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
	c.noDeadline, c.ignoreDeadline = true, true
	c.respond = func(q *dns.Msg, dst M.Socksaddr) []udpTestPacket { return []udpTestPacket{udpAnswer(q, dst, nil)} }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeUDPTargets(ctx, udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst}); err != nil {
		t.Fatalf("без поддержки deadline: %v", err)
	}
	// И без ответа проба кончается по сроку, а не висит.
	c2 := newUDPTestConn()
	c2.noDeadline, c2.ignoreDeadline = true, true
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if err := probeUDPTargets(ctx2, udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c2}}, []M.Socksaddr{dst}); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if time.Since(start) > time.Second {
		t.Fatal("проба зависла")
	}
}

func TestProbeUDPTimeout(t *testing.T) {
	dst := M.ParseSocksaddrHostPort("1.1.1.1", 53)
	c := newUDPTestConn()
	start := time.Now()
	err := probeUDPTargets(context.Background(), udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst})
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if elapsed := time.Since(start); elapsed < ProbeUDPTimeout-100*time.Millisecond || elapsed > 4500*time.Millisecond {
		t.Fatalf("тайм-аут: %v", elapsed)
	}
}

func TestProbeUDPParallel(t *testing.T) {
	first, second := M.ParseSocksaddrHostPort("1.1.1.1", 53), M.ParseSocksaddrHostPort("8.8.8.8", 53)
	silent, good := newUDPTestConn(), newUDPTestConn()
	silent.ignoreDeadline = true
	good.respond = func(q *dns.Msg, dst M.Socksaddr) []udpTestPacket {
		// Вторая цель отвечает, только когда первая уже ждёт ответа.
		<-silent.written
		return []udpTestPacket{udpAnswer(q, dst, nil)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ProbeUDP(ctx, udpTestDialer{map[M.Socksaddr]*udpTestConn{first: silent, second: good}}); err != nil {
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
	c.ignoreDeadline = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- probeUDPTargets(ctx, udpTestDialer{map[M.Socksaddr]*udpTestConn{dst: c}}, []M.Socksaddr{dst})
	}()
	select {
	case <-c.written:
	case <-time.After(time.Second):
		t.Fatal("запрос не отправлен")
	}
	cancel()
	select {
	case err := <-result:
		if err != ctx.Err() {
			t.Fatalf("получено %v, ожидалось %v", err, ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("отмена не прервала чтение")
	}
	select {
	case <-c.closed:
	default:
		t.Fatal("отмена не закрыла соединение")
	}
}

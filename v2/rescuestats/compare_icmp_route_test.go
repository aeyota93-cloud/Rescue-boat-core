package rescuestats

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// plainOutbound — прямой выход без ICMP (только adapter.Outbound).
type plainOutbound struct{}

func (plainOutbound) Type() string           { return C.TypeDirect }
func (plainOutbound) Tag() string            { return "direct" }
func (plainOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (plainOutbound) Dependencies() []string { return nil }
func (plainOutbound) DisplayType() string    { return "Direct" }
func (plainOutbound) IsReady() bool          { return true }
func (plainOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("не нужен")
}
func (plainOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("не нужен")
}

// fakeRouteOutbound — прямой выход с ICMP: отвечает на echo через delay, как sing-tun/ping.
type fakeRouteOutbound struct {
	plainOutbound
	delay   time.Duration
	openErr error
	panics  bool
	silent  bool // запрос уходит, ответа нет
	wrongID bool // отвечает чужим id
	opened  atomic.Int32
	meta    atomic.Value // adapter.InboundContext
}

func (o *fakeRouteOutbound) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	if o.panics {
		var dialer any = "not a DefaultDialer"
		_ = dialer.(interface{ Control() })
	}
	if o.openErr != nil {
		return nil, o.openErr
	}
	o.opened.Add(1)
	o.meta.Store(metadata)
	return &fakeRouteDest{o: o, ctx: routeContext}, nil
}

type fakeRouteDest struct {
	o      *fakeRouteOutbound
	ctx    tun.DirectRouteContext
	closed atomic.Bool
}

func (d *fakeRouteDest) WritePacket(packet *buf.Buffer) error {
	defer packet.Release()
	pkt := append([]byte(nil), packet.Bytes()...)
	if d.o.silent {
		return nil
	}
	reply, err := echoReplyFor(pkt, d.o.wrongID)
	if err != nil {
		return err
	}
	go func() {
		time.Sleep(d.o.delay)
		if !d.closed.Load() {
			_ = d.ctx.WritePacket(reply)
		}
	}()
	return nil
}

func (d *fakeRouteDest) Close() error   { d.closed.Store(true); return nil }
func (d *fakeRouteDest) IsClosed() bool { return d.closed.Load() }

// echoReplyFor собирает ответ на запрос: адреса меняются местами, тип — echo reply.
func echoReplyFor(req []byte, wrongID bool) ([]byte, error) {
	v6 := req[0]>>4 == 6
	hl, proto := ipv4.HeaderLen, 1
	if v6 {
		hl, proto = ipv6.HeaderLen, 58
	}
	msg, err := icmp.ParseMessage(proto, req[hl:])
	if err != nil {
		return nil, err
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, errors.New("не echo")
	}
	if wrongID {
		echo.ID++
	}
	if v6 {
		if msg.Type != ipv6.ICMPTypeEchoRequest {
			return nil, errors.New("не echo request")
		}
		msg.Type = ipv6.ICMPTypeEchoReply
	} else {
		if msg.Type != ipv4.ICMPTypeEcho {
			return nil, errors.New("не echo request")
		}
		if ipv4Checksum(req[:hl]) != 0 {
			return nil, errors.New("контрольная сумма IPv4-заголовка")
		}
		msg.Type = ipv4.ICMPTypeEchoReply
	}
	body, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), req[:hl]...)
	if v6 {
		copy(out[8:24], req[24:40])
		copy(out[24:40], req[8:24])
	} else {
		copy(out[12:16], req[16:20])
		copy(out[16:20], req[12:16])
	}
	return append(out, body...), nil
}

func TestOutboundPingViaDirectRoute(t *testing.T) {
	for _, addr := range []string{"93.184.216.34", "2001:db8::34"} {
		ip := netip.MustParseAddr(addr)
		ob := &fakeRouteOutbound{delay: 30 * time.Millisecond}
		var fallbacks atomic.Int32
		ping := newOutboundPing(func() adapter.Outbound { return ob }, func(context.Context, netip.Addr, time.Duration) (time.Duration, error) {
			fallbacks.Add(1)
			return time.Millisecond, nil
		})
		d, err := ping(context.Background(), ip, time.Second)
		if err != nil || d < 30*time.Millisecond || d > time.Second {
			t.Errorf("%s: d=%v err=%v", addr, d, err)
		}
		if fallbacks.Load() != 0 || ob.opened.Load() != 1 {
			t.Errorf("%s: системный ping %d, открытий %d", addr, fallbacks.Load(), ob.opened.Load())
		}
		meta := ob.meta.Load().(adapter.InboundContext)
		if meta.Network != N.NetworkICMP || meta.Destination.Addr != ip || meta.Source.Addr.Is4() != ip.Is4() {
			t.Errorf("%s: metadata %+v", addr, meta)
		}
	}
}

func TestOutboundPingTimeoutAndForeignReply(t *testing.T) {
	ip := netip.MustParseAddr("93.184.216.34")
	fallback := func(context.Context, netip.Addr, time.Duration) (time.Duration, error) {
		t.Error("системный ping вместо таймаута")
		return 0, nil
	}
	for name, ob := range map[string]*fakeRouteOutbound{
		"тишина":   {silent: true},
		"чужой id": {wrongID: true},
	} {
		start := time.Now()
		_, err := newOutboundPing(func() adapter.Outbound { return ob }, fallback)(context.Background(), ip, 100*time.Millisecond)
		if err == nil || time.Since(start) > time.Second {
			t.Errorf("%s: err=%v за %v", name, err, time.Since(start))
		}
	}
}

func TestOutboundPingFallsBackToSystem(t *testing.T) {
	ip := netip.MustParseAddr("93.184.216.34")
	for name, ob := range map[string]adapter.Outbound{
		"без ICMP":   plainOutbound{},
		"нет прав":   &fakeRouteOutbound{openErr: errors.New("socket: access is denied")},
		"паника":     &fakeRouteOutbound{panics: true},
		"выхода нет": nil,
	} {
		var fallbacks atomic.Int32
		ping := newOutboundPing(func() adapter.Outbound { return ob }, func(context.Context, netip.Addr, time.Duration) (time.Duration, error) {
			fallbacks.Add(1)
			return 7 * time.Millisecond, nil
		})
		d, err := ping(context.Background(), ip, time.Second)
		if err != nil || d != 7*time.Millisecond || fallbacks.Load() != 1 {
			t.Errorf("%s: d=%v err=%v системных %d", name, d, err, fallbacks.Load())
		}
	}
}

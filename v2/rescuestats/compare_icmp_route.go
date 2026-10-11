package rescuestats

// ICMP echo через прямой выход ядра (adapter.DirectRouteOutbound, как пинги из туннеля в
// sing-box 1.13): сокет привязан к физическому интерфейсу так же, как TCP прямого выхода,
// поэтому ping не попадает обратно в TUN. Если выход так не умеет или ОС не дала открыть
// ICMP-сокет (на Windows сырой сокет требует администратора) — системный ping (systemPing).

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Условный адрес «отправителя» в собранном IP-пакете: ядро подменяет его своим, а ответ
// возвращает с ним же в адресе получателя. Наружу не уходит.
var (
	routePingSrc4 = netip.MustParseAddr("172.19.0.1")
	routePingSrc6 = netip.MustParseAddr("fdfe:dcba:9876::1")
)

// routeDestination — то, что возвращает NewDirectRouteConnection (tun.DirectRouteDestination).
type routeDestination interface {
	WritePacket(packet *buf.Buffer) error
	Close() error
}

// routeReplies принимает IP-пакеты ответов от выхода (tun.DirectRouteContext).
type routeReplies struct{ ch chan []byte }

func (r *routeReplies) WritePacket(packet []byte) error {
	select {
	case r.ch <- append([]byte(nil), packet...):
	default: // ждём один ответ, лишние не нужны
	}
	return nil
}

// newOutboundPing — ping через прямой выход с запасным системным.
func newOutboundPing(direct func() adapter.Outbound, fallback icmpFunc) icmpFunc {
	return func(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, error) {
		if direct != nil {
			if ob := direct(); ob != nil {
				if d, handled, err := outboundPing(ctx, ob, ip, timeout); handled {
					return d, err
				}
			}
		}
		return fallback(ctx, ip, timeout)
	}
}

// outboundPing: handled=false — выход не умеет ICMP или сокет не открылся (пробовать иначе).
func outboundPing(ctx context.Context, ob adapter.Outbound, ip netip.Addr, timeout time.Duration) (time.Duration, bool, error) {
	route, ok := ob.(adapter.DirectRouteOutbound)
	if !ok {
		return 0, false, nil
	}
	ip = ip.Unmap()
	replies := &routeReplies{ch: make(chan []byte, 1)}
	dest, err := openRouteDestination(route, ip, replies, timeout)
	if err != nil || dest == nil {
		return 0, false, nil
	}
	defer dest.Close()

	id := uint16(os.Getpid())
	seq := uint16(icmpSeq.Add(1))
	packet, err := buildEchoPacket(ip, id, seq)
	if err != nil {
		return 0, false, nil
	}
	buffer := buf.NewPacket()
	if _, err := buffer.Write(packet); err != nil {
		buffer.Release()
		return 0, false, nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	start := time.Now()
	if err := dest.WritePacket(buffer); err != nil {
		return 0, true, err
	}
	for {
		select {
		case <-ctx.Done():
			return 0, true, ctx.Err()
		case <-timer.C:
			return 0, true, errors.New("таймаут")
		case reply := <-replies.ch:
			if isEchoReply(reply, ip, id, seq) {
				return time.Since(start), true, nil
			}
		}
	}
}

// openRouteDestination: прямой выход sing-box приводит свой dialer к *DefaultDialer через
// MustCast — паника на непривычной настройке не должна ронять ядро.
func openRouteDestination(route adapter.DirectRouteOutbound, ip netip.Addr, replies *routeReplies, timeout time.Duration) (dest routeDestination, err error) {
	defer func() {
		if p := recover(); p != nil {
			dest, err = nil, fmt.Errorf("ICMP через прямой выход: %v", p)
		}
	}()
	metadata := adapter.InboundContext{
		Network:     N.NetworkICMP,
		Destination: M.Socksaddr{Addr: ip},
	}
	if ip.Is4() {
		metadata.Source = M.Socksaddr{Addr: routePingSrc4}
	} else {
		metadata.Source = M.Socksaddr{Addr: routePingSrc6}
	}
	d, err := route.NewDirectRouteConnection(metadata, replies, timeout)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, errors.New("выход не открыл ICMP")
	}
	return d, nil
}

// buildEchoPacket — IP-пакет с ICMP echo request (так выход принимает пакеты из TUN).
func buildEchoPacket(ip netip.Addr, id, seq uint16) ([]byte, error) {
	data := []byte("prichal-compare")
	if ip.Is4() {
		body, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: data}}).Marshal(nil)
		if err != nil {
			return nil, err
		}
		pkt := make([]byte, ipv4.HeaderLen+len(body))
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
		pkt[8] = 64 // TTL
		pkt[9] = 1  // ICMP
		src, dst := routePingSrc4.As4(), ip.As4()
		copy(pkt[12:16], src[:])
		copy(pkt[16:20], dst[:])
		binary.BigEndian.PutUint16(pkt[10:], ipv4Checksum(pkt[:ipv4.HeaderLen]))
		copy(pkt[ipv4.HeaderLen:], body)
		return pkt, nil
	}
	src, dst := routePingSrc6.As16(), ip.As16()
	body, err := (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: data}}).
		Marshal(icmp.IPv6PseudoHeader(src[:], dst[:]))
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, ipv6.HeaderLen+len(body))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(body)))
	pkt[6] = 58 // ICMPv6
	pkt[7] = 64 // hop limit
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	copy(pkt[ipv6.HeaderLen:], body)
	return pkt, nil
}

// isEchoReply — IP-пакет ответа от ip с нашими id/seq.
func isEchoReply(pkt []byte, ip netip.Addr, id, seq uint16) bool {
	var (
		from    netip.Addr
		payload []byte
		proto   int
		want    icmp.Type
	)
	switch {
	case len(pkt) >= ipv4.HeaderLen && pkt[0]>>4 == 4:
		hl := int(pkt[0]&0x0f) * 4
		if hl < ipv4.HeaderLen || len(pkt) < hl {
			return false
		}
		from = netip.AddrFrom4([4]byte(pkt[12:16]))
		payload, proto, want = pkt[hl:], 1, ipv4.ICMPTypeEchoReply
	case len(pkt) >= ipv6.HeaderLen && pkt[0]>>4 == 6:
		from = netip.AddrFrom16([16]byte(pkt[8:24]))
		payload, proto, want = pkt[ipv6.HeaderLen:], 58, ipv6.ICMPTypeEchoReply
	default:
		return false
	}
	if from.Unmap() != ip {
		return false
	}
	msg, err := icmp.ParseMessage(proto, payload)
	if err != nil || msg.Type != want {
		return false
	}
	echo, ok := msg.Body.(*icmp.Echo)
	return ok && uint16(echo.ID) == id && uint16(echo.Seq) == seq
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

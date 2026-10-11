package rescuestats

// Системный ICMP echo для метода icmp в «Сравнить пути» — запасной путь, когда прямой выход
// ядра не смог отправить ping сам (compare_icmp_route.go): на Windows — системный IcmpSendEcho
// (права администратора не нужны), иначе сырой/датаграммный сокет golang.org/x/net/icmp.
// При включённом TUN такой ping идёт по таблице маршрутов, то есть через ядро.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// errICMPNoPermission — ОС не дала открыть ICMP-сокет (нет прав).
var errICMPNoPermission = errors.New("нет прав на ICMP")

// icmpFunc — один ping; подменяется в тестах.
type icmpFunc func(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, error)

var icmpSeq atomic.Uint32

func systemPing(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, error) {
	if d, handled, err := nativePing(ip, timeout); handled {
		return d, err
	}
	return socketPing(ctx, ip, timeout)
}

// socketPing — echo через x/net/icmp: сначала сырой сокет, затем «непривилегированный» UDP.
func socketPing(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, error) {
	ip = ip.Unmap()
	var (
		networks []string
		proto    int
		echoType icmp.Type
		replyTyp icmp.Type
		listen   string
	)
	if ip.Is4() {
		networks, proto, echoType, replyTyp, listen = []string{"ip4:icmp", "udp4"}, 1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, "0.0.0.0"
	} else {
		networks, proto, echoType, replyTyp, listen = []string{"ip6:ipv6-icmp", "udp6"}, 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, "::"
	}
	var (
		conn    *icmp.PacketConn
		network string
		err     error
	)
	for _, network = range networks {
		conn, err = icmp.ListenPacket(network, listen)
		if err == nil {
			break
		}
	}
	if err != nil {
		if isPermissionErr(err) {
			return 0, errICMPNoPermission
		}
		return 0, err
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	seq := int(icmpSeq.Add(1) & 0xffff)
	msg := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("prichal-compare")}}
	payload, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	var dst net.Addr = &net.IPAddr{IP: ip.AsSlice()}
	if strings.HasPrefix(network, "udp") {
		dst = &net.UDPAddr{IP: ip.AsSlice()}
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	start := time.Now()
	if _, err := conn.WriteTo(payload, dst); err != nil {
		if isPermissionErr(err) {
			return 0, errICMPNoPermission
		}
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		reply, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || reply.Type != replyTyp {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if !ok || echo.Seq != seq {
			continue
		}
		// У сырого сокета ответ может прийти от чужого адреса (чужой ping): сверяем отправителя.
		if !sameAddr(from, ip) {
			continue
		}
		return time.Since(start), nil
	}
}

func sameAddr(from net.Addr, ip netip.Addr) bool {
	var raw net.IP
	switch a := from.(type) {
	case *net.IPAddr:
		raw = a.IP
	case *net.UDPAddr:
		raw = a.IP
	default:
		return true
	}
	got, ok := netip.AddrFromSlice(raw)
	return ok && got.Unmap() == ip.Unmap()
}

func isPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "permission") || strings.Contains(text, "access is denied") ||
		strings.Contains(text, "operation not permitted") || strings.Contains(text, "forbidden")
}

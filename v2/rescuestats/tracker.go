package rescuestats

// Слежение за соединениями программ: ядро зовёт RoutedConnection для каждого соединения
// после выбора маршрута (adapter.ConnectionTracker). Обёртка ничего не меняет в передаче данных
// (счётчики снимаются так же, как в Clash API), а только узнаёт:
//   - неудачный dial — sing-box сообщает его через HandshakeFailure;
//   - момент установления — ConnHandshakeSuccess / PacketConnHandshakeSuccess;
//   - сколько отправлено и получено — для «замираний» UDP и правила «EOF после данных».
// Ошибки уже установленного соединения sing-box только пишет в журнал — их берёт logs.go
// по номеру соединения из журнала (log ID в контексте).

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	RouteVPN    = "vpn"
	RouteDirect = "direct"
	RouteBlock  = "block"
)

// connInfo — неизменяемые сведения о соединении и атомарные счётчики.
type connInfo struct {
	logID       uint32
	hasLogID    bool
	app         string
	host        string
	ip          string
	port        int
	network     string
	route       string
	programAddr string // адрес программы: ошибки с ним — со стороны программы, не сети
	created     time.Time

	up          atomic.Int64
	down        atomic.Int64
	established atomic.Int64 // unix nano; 0 — не установлено
	closedAt    atomic.Int64 // unix nano; 0 — открыто
	errored     atomic.Bool

	stall stallDetector // только из горутины обслуживания
}

func newConnInfo(ctx context.Context, metadata adapter.InboundContext, network, route string, now time.Time) *connInfo {
	info := &connInfo{
		network: network,
		route:   route,
		created: now,
		port:    int(metadata.Destination.Port),
	}
	if id, ok := log.IDFromContext(ctx); ok {
		info.logID, info.hasLogID = id.ID, true
	}
	if metadata.ProcessInfo != nil {
		info.app = exeName(metadata.ProcessInfo.ProcessPath)
	}
	switch {
	case metadata.Domain != "":
		info.host = metadata.Domain
	case metadata.Destination.IsFqdn():
		info.host = metadata.Destination.Fqdn
	}
	switch {
	case metadata.Destination.IsIP():
		info.ip = metadata.Destination.Addr.Unmap().String()
	case len(metadata.DestinationAddresses) > 0:
		info.ip = metadata.DestinationAddresses[0].Unmap().String()
	}
	if metadata.Source.IsValid() {
		info.programAddr = metadata.Source.String()
	}
	return info
}

// exeName — имя exe без пути (путь может быть и с \, и с /).
func exeName(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// routeOf — итоговый outbound после групп (selector, urltest): direct, block или vpn.
func routeOf(outbounds adapter.OutboundManager, matchOutbound adapter.Outbound) string {
	var current adapter.Outbound = matchOutbound
	if current == nil && outbounds != nil {
		current = outbounds.Default()
	}
	for i := 0; i < 8 && current != nil; i++ {
		group, isGroup := current.(adapter.OutboundGroup)
		if !isGroup || outbounds == nil {
			break
		}
		next, loaded := outbounds.Outbound(group.Now())
		if !loaded {
			break
		}
		current = next
	}
	if current == nil {
		return RouteVPN
	}
	switch current.Type() {
	case C.TypeDirect:
		return RouteDirect
	case C.TypeBlock:
		return RouteBlock
	}
	return RouteVPN
}

// trackedConn — обёртка TCP-соединения программы.
type trackedConn struct {
	N.ExtendedConn
	info  *connInfo
	run   *run
	close sync.Once
}

func newTrackedConn(conn net.Conn, info *connInfo, r *run) *trackedConn {
	return &trackedConn{
		ExtendedConn: bufio.NewCounterConn(conn,
			[]N.CountFunc{func(n int64) { info.up.Add(n) }},
			[]N.CountFunc{func(n int64) { info.down.Add(n) }}),
		info: info,
		run:  r,
	}
}

func (c *trackedConn) HandshakeFailure(err error) error {
	c.run.connError(c.info, err.Error(), err)
	return forwardHandshakeFailure(c.ExtendedConn, err)
}

func (c *trackedConn) ConnHandshakeSuccess(conn net.Conn) error {
	c.info.established.CompareAndSwap(0, c.run.now().UnixNano())
	return N.ReportConnHandshakeSuccess(c.ExtendedConn, conn)
}

func (c *trackedConn) Close() error {
	c.close.Do(func() { c.run.connClosed(c.info) })
	return c.ExtendedConn.Close()
}

func (c *trackedConn) Upstream() any           { return c.ExtendedConn }
func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

// trackedPacketConn — обёртка UDP-соединения программы.
type trackedPacketConn struct {
	N.PacketConn
	info  *connInfo
	run   *run
	close sync.Once
}

func newTrackedPacketConn(conn N.PacketConn, info *connInfo, r *run) *trackedPacketConn {
	return &trackedPacketConn{
		PacketConn: bufio.NewCounterPacketConn(conn,
			[]N.CountFunc{func(n int64) { info.up.Add(n) }},
			[]N.CountFunc{func(n int64) { info.down.Add(n) }}),
		info: info,
		run:  r,
	}
}

func (c *trackedPacketConn) HandshakeFailure(err error) error {
	c.run.connError(c.info, err.Error(), err)
	return forwardHandshakeFailure(c.PacketConn, err)
}

func (c *trackedPacketConn) PacketConnHandshakeSuccess(conn net.PacketConn) error {
	c.info.established.CompareAndSwap(0, c.run.now().UnixNano())
	return N.ReportPacketConnHandshakeSuccess(c.PacketConn, conn)
}

func (c *trackedPacketConn) Close() error {
	c.close.Do(func() { c.run.connClosed(c.info) })
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return true }

// forwardHandshakeFailure делает то же, что N.CloseOnHandshakeFailure сделал бы без нашей
// обёртки: передаёт ошибку входу (например, SOCKS-ответ) или сбрасывает TCP (linger 0).
func forwardHandshakeFailure(upstream any, err error) error {
	if h, ok := common.Cast[N.HandshakeFailure](upstream); ok {
		return h.HandshakeFailure(err)
	}
	if tcp, ok := common.Cast[interface{ SetLinger(sec int) error }](upstream); ok {
		_ = tcp.SetLinger(0)
	}
	return nil
}

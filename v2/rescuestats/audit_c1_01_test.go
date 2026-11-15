package rescuestats

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/group/balancer"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type auditC101Manager struct {
	adapter.OutboundManager
	outs map[string]adapter.Outbound
}

func (m *auditC101Manager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outs[tag]
	return o, ok
}

type auditC101Dialer struct {
	outbound.Adapter
	server string
	last   *string
}

func (o *auditC101Dialer) DialContext(_ context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	*o.last = o.server
	a, b := net.Pipe()
	b.Close()
	return a, nil
}
func (o *auditC101Dialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	*o.last = o.server
	return &auditC101Packet{}, nil
}

// Пакетное соединение из памяти: тесту нужен только результат выбора выхода.
type auditC101Packet struct{ net.PacketConn }

func (*auditC101Packet) Close() error { return nil }

func TestAudit_C1_01_LanesPreserveBalancerRouting(t *testing.T) {
	for _, strategy := range []string{balancer.StrategyRoundRobin, balancer.StrategyStickySessions, balancer.StrategyConsistentHashing, balancer.StrategyLowestDelay} {
		t.Run(strategy, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("C1-01: ожидалась маршрутизация без паники, получено %v", p)
				}
			}()
			var last string
			outs := make(map[string]adapter.Outbound)
			for _, server := range []string{"A", "B"} {
				networks := []string{"tcp", "udp"}
				if strategy == balancer.StrategyLowestDelay {
					if server == "A" {
						networks = []string{"tcp"}
					} else {
						networks = []string{"udp"}
					}
				}
				for _, tag := range []string{server, server + " #0"} {
					outs[tag] = &auditC101Dialer{Adapter: outbound.NewAdapter("socks", tag, networks, nil), server: server, last: &last}
				}
			}
			manager := &auditC101Manager{outs: outs}
			ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
			logger := log.NewNOPFactory().Logger()
			// Один выбор без повторных попыток: мониторинг в этом тесте выключен.
			ob, err := balancer.NewLoadBalance(ctx, nil, logger, "balance", option.BalancerOutboundOptions{Strategy: strategy, Outbounds: []string{"A", "B"}, MaxRetry: 1, DelayAcceptableRatio: 2})
			if err != nil {
				t.Fatalf("C1-01: ожидалось создание балансировщика, получено %v", err)
			}
			balance := ob.(*balancer.Balancer)
			if err := balance.Start(); err != nil {
				t.Fatalf("C1-01: ожидался Start балансировщика без ошибки, получено %v", err)
			}
			defer balance.Close()
			outs["balance"] = balance
			selected, err := group.NewSelector(ctx, nil, logger, "select", option.SelectorOutboundOptions{Outbounds: []string{"balance", "A", "B"}, Default: "balance"})
			if err != nil {
				t.Fatalf("C1-01: ожидался основной selector, получено %v", err)
			}
			if err := selected.(*group.Selector).Start(); err != nil {
				t.Fatalf("C1-01: ожидался Start основного selector, получено %v", err)
			}
			outs["select"] = selected
			laneManager := &auditC101Manager{outs: map[string]adapter.Outbound{"A #0": outs["A #0"], "B #0": outs["B #0"]}}
			laneCtx := service.ContextWith[adapter.OutboundManager](context.Background(), laneManager)
			laneOut, err := group.NewSelector(laneCtx, nil, logger, "lane-0", option.SelectorOutboundOptions{Outbounds: []string{"A #0", "B #0"}, Default: "A #0"})
			if err != nil {
				t.Fatalf("C1-01: ожидался selector полосы, получено %v", err)
			}
			lane := laneOut.(*group.Selector)
			if err := lane.Start(); err != nil {
				t.Fatalf("C1-01: ожидался Start полосы без ошибки, получено %v", err)
			}
			// Selector уже сохранил выходы. Убираем их из тестового manager,
			// чтобы SelectOutbound не запускал настоящий активный мониторинг.
			laneManager.outs = nil
			// Тот же tick, что вызывает LaneSync.Start, без фонового таймера.
			syncLanes([]laneGroup{lane}, leafOf(manager.Outbound, "select"), func(server string, n int) string { return fmt.Sprintf("%s #%d", server, n) })
			networks := []string{"tcp"}
			if strategy == balancer.StrategyLowestDelay {
				networks = append(networks, "udp")
			}
			for _, network := range networks {
				// Сначала целая серия через исходную группу, затем через полосу.
				// 128 запросов возвращают round-robin в исходную фазу; sticky/hash
				// получают те же metadata и используют тот же экземпляр стратегии.
				var want [128]string
				mismatches := 0
				for phase := 0; phase < 2; phase++ {
					var dialer adapter.Outbound = balance
					callCtx := ctx
					if phase == 1 {
						dialer, callCtx = lane, laneCtx
					}
					for i := range want {
						metadata := adapter.InboundContext{Domain: fmt.Sprintf("host-%d.example", i), Source: M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:1234", i+1)), Destination: M.ParseSocksaddr("198.51.100.1:443")}
						requestCtx := adapter.WithContext(callCtx, &metadata)
						if network == "udp" {
							conn, err := dialer.ListenPacket(requestCtx, metadata.Destination)
							if err != nil {
								t.Fatalf("C1-01: ожидался UDP без ошибки в фазе %d, получено %v", phase, err)
							}
							conn.Close()
						} else {
							conn, err := dialer.DialContext(requestCtx, network, metadata.Destination)
							if err != nil {
								t.Fatalf("C1-01: ожидался TCP без ошибки в фазе %d, получено %v", phase, err)
							}
							conn.Close()
						}
						if phase == 0 {
							want[i] = last
						} else if last != want[i] {
							mismatches++
						}
					}
				}
				if mismatches != 0 {
					t.Errorf("C1-01: ожидалось сохранение стратегии %s для %s в полосе, %d из 128 выборов отличаются; полоса осталась на %q", strategy, network, mismatches, lane.Now())
				}
			}
		})
	}
}

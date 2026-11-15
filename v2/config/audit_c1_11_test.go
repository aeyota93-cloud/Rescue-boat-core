package config

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/balancer"
	"github.com/sagernet/sing/service"
)

type auditC111Manager struct {
	adapter.OutboundManager
	outs map[string]adapter.Outbound
}

func (m *auditC111Manager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outs[tag]
	return o, ok
}

// Start балансировщика использует только Tag и Network конечных выходов.
type auditC111Outbound struct {
	adapter.Outbound
	tag string
}

func (o *auditC111Outbound) Tag() string       { return o.tag }
func (o *auditC111Outbound) Network() []string { return []string{"tcp", "udp"} }

func TestAudit_C1_11_DefaultOptionsProduceStartableBalancer(t *testing.T) {
	h := DefaultHiddifyOptions()
	h.ConnectionTestUrls = []string{"http://192.0.2.1/generate_204"}
	h.EnableClashApi = false
	h.LogFile = ""
	built, err := BuildConfig(context.Background(), h, &ReadOptions{Options: auditC1Servers()})
	if err != nil {
		t.Fatalf("C1-11: ожидалась сборка с настройками по умолчанию, получено %v", err)
	}
	var opts *option.BalancerOutboundOptions
	for _, out := range built.Outbounds {
		if out.Tag == OutboundRoundRobinTag {
			opts, _ = out.Options.(*option.BalancerOutboundOptions)
		}
	}
	if opts == nil {
		t.Fatal("C1-11: ожидался выход balance для двух серверов, выход отсутствует")
	}
	m := &auditC111Manager{outs: map[string]adapter.Outbound{"A": &auditC111Outbound{tag: "A"}, "B": &auditC111Outbound{tag: "B"}}}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), m)
	out, err := balancer.NewLoadBalance(ctx, nil, log.NewNOPFactory().Logger(), "balance", *opts)
	if err != nil {
		t.Fatalf("C1-11: ожидалось создание balance, получено %v", err)
	}
	b := out.(*balancer.Balancer)
	defer b.Close()
	// Без PostStart: мониторинг и соединения не запускаются.
	if err := b.Start(); err != nil {
		t.Fatalf("C1-11: ожидался успешный Start balance со стратегией по умолчанию, получена стратегия %q и ошибка %v", b.Strategy(), err)
	}
	if b.Strategy() == "" {
		t.Fatal("C1-11: ожидалась непустая поддерживаемая стратегия, получена пустая")
	}
}

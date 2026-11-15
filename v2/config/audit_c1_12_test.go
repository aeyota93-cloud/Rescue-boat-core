package config

import (
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestAudit_C1_12_NetworkAndIPVersionOnlyRulesSurvive(t *testing.T) {
	for _, target := range []Outbound{Outbound_direct, Outbound_block} {
		t.Run("user-"+target.String(), func(t *testing.T) {
			h := auditC1Options()
			h.Rules = []Rule{{Enabled: true, Network: Network_udp, Outbound: target}, {Enabled: true, Outbound: target}, {Enabled: false, Network: Network_udp, Outbound: target}}
			got := userRules(h).route
			if len(got) != 1 {
				t.Fatalf("C1-12: ожидалось одно включённое UDP-правило без пустого и выключенного, получено %d", len(got))
			}
			r := got[0].DefaultOptions
			if !reflect.DeepEqual([]string(r.Network), []string{"udp"}) {
				t.Errorf("C1-12: ожидалось условие network=udp, получено %v", r.Network)
			}
			if target == Outbound_direct && r.RouteOptions.Outbound != OutboundDirectTag || target == Outbound_block && r.Action != "reject" {
				t.Errorf("C1-12: ожидалось действие %s, получено %+v", target, r.RuleAction)
			}
		})
	}
	for _, raw := range []option.RawDefaultRule{{Network: []string{"udp"}}, {IPVersion: 6}} {
		name := "server-network"
		if raw.IPVersion != 0 {
			name = "server-ip-version"
		}
		t.Run(name, func(t *testing.T) {
			input := &option.Options{Outbounds: []option.Outbound{{Tag: "direct", Type: "direct"}}, Route: &option.RouteOptions{Rules: []option.Rule{
				{DefaultOptions: option.DefaultRule{RawDefaultRule: raw, RuleAction: routeAction("direct")}},
				{DefaultOptions: option.DefaultRule{RuleAction: routeAction("direct")}},
			}}}
			got := serverRules(input, auditC1Options()).route
			if len(got) != 1 {
				t.Fatalf("C1-12: ожидалось одно серверное правило с условием и без пустого, получено %d", len(got))
			}
			if !reflect.DeepEqual(got[0].DefaultOptions.RawDefaultRule, raw) || got[0].DefaultOptions.RouteOptions.Outbound != OutboundDirectTag {
				t.Errorf("C1-12: ожидалось сохранение условия и прямого выхода, получено %+v", got[0])
			}
		})
	}
}

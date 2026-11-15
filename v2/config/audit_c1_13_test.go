package config

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
)

func TestAudit_C1_13_ServerDNSRulePreservesInvert(t *testing.T) {
	original := option.DefaultDNSRule{RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: []string{"example.com"}, Invert: true}, DNSRuleAction: option.DNSRuleAction{RouteOptions: option.DNSRouteActionOptions{Server: "local"}}}
	input := &option.Options{Route: &option.RouteOptions{}, DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Final: "remote", Rules: []option.DNSRule{{DefaultOptions: original}}}}}
	got := serverRules(input, auditC1Options()).dns
	if len(got) != 1 {
		t.Fatalf("C1-13: ожидалось одно перенесённое DNS-правило, получено %d", len(got))
	}
	if !got[0].Invert {
		t.Error("C1-13: ожидалось сохранение invert=true, получено false")
	}
	logger := log.NewNOPFactory().Logger()
	before, err := rule.NewDefaultDNSRule(context.Background(), logger, original)
	if err != nil {
		t.Fatalf("C1-13: ожидался исходный DNS matcher, получено %v", err)
	}
	after, err := rule.NewDefaultDNSRule(context.Background(), logger, got[0])
	if err != nil {
		t.Fatalf("C1-13: ожидался перенесённый DNS matcher, получено %v", err)
	}
	for _, domain := range []string{"example.com", "other.example"} {
		want := before.Match(&adapter.InboundContext{Domain: domain})
		if actual := after.Match(&adapter.InboundContext{Domain: domain}); actual != want {
			t.Errorf("C1-13: для %s ожидалось совпадение %t как до переноса, получено %t", domain, want, actual)
		}
	}
}

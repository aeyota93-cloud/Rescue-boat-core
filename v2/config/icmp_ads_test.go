package config

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func routeIdx(o *option.Options, match func(option.DefaultRule) bool) int {
	for i, r := range o.Route.Rules {
		if match(r.DefaultOptions) {
			return i
		}
	}
	return -1
}

func dnsIdx(o *option.Options, match func(option.DefaultDNSRule) bool) int {
	for i, r := range o.DNS.Rules {
		if match(r.DefaultOptions) {
			return i
		}
	}
	return -1
}

func isICMPRule(r option.DefaultRule) bool { return slices.Contains(r.Network, "icmp") }

// Пинги идут напрямую и стоят выше раздельного туннеля, правил сервера и блокировки рекламы.
func TestICMPRoutedDirectFirst(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.BlockAds = true
	hopt.SplitTunnelDir = filepath.Join(t.TempDir(), "split")
	o := buildTestConfig(t, testSubscription, hopt)

	icmp := routeIdx(o, isICMPRule)
	if icmp < 0 {
		t.Fatal("нет правила для ICMP")
	}
	rule := o.Route.Rules[icmp].DefaultOptions
	if rule.Action != "route" && rule.Action != "" || rule.RouteOptions.Outbound != OutboundDirectTag {
		t.Errorf("ICMP должен идти напрямую: %+v", rule)
	}
	if len(rule.Network) != 1 || len(rule.RuleSet) != 0 || len(rule.IPCIDR) != 0 || len(rule.Domain) != 0 {
		t.Errorf("правило ICMP должно быть безусловным по адресу: %+v", rule)
	}

	hijack := routeIdx(o, func(r option.DefaultRule) bool { return r.Action == "hijack-dns" })
	if hijack < 0 || icmp != hijack+1 {
		t.Errorf("ICMP сразу после hijack-dns: hijack=%d, icmp=%d", hijack, icmp)
	}
	for name, match := range map[string]func(option.DefaultRule) bool{
		"через VPN":    func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) },
		"мимо VPN":     func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitBypassTag) },
		"локальная":    func(r option.DefaultRule) bool { return r.IPIsPrivate },
		"сервер":       func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "server-ru-ip") },
		"реклама":      func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "geosite-ads") },
		"внутренняя":   func(r option.DefaultRule) bool { return slices.Contains(r.IPCIDR, "10.10.34.0/24") },
		"только VPN":   func(r option.DefaultRule) bool { return slices.Contains(r.Domain, "only-vpn.example") },
		"реклама сайт": func(r option.DefaultRule) bool { return slices.Contains(r.DomainSuffix, "ads.example") },
	} {
		i := routeIdx(o, match)
		if i < 0 {
			t.Errorf("правило %q не найдено", name)
			continue
		}
		if i < icmp {
			t.Errorf("правило %q (%d) стоит выше ICMP (%d)", name, i, icmp)
		}
	}
	// Остальные правила не должны сами цепляться за ICMP.
	for i, r := range o.Route.Rules {
		if i != icmp && isICMPRule(r.DefaultOptions) {
			t.Errorf("лишнее правило ICMP: %d", i)
		}
	}
}

// Итоговый конфиг с ICMP-правилом принимает сам sing-box (создание экземпляра без запуска).
func TestICMPConfigPassesSingBoxCheck(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.BlockAds = true
	hopt.SplitTunnelDir = filepath.Join(t.TempDir(), "split")
	o := buildTestConfig(t, testSubscription, hopt)
	if err := libbox.CheckConfigOptions(o); err != nil {
		t.Fatalf("sing-box не принял конфиг: %v", err)
	}
}

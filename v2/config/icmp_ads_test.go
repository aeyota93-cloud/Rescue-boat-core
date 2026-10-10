package config

import (
	"fmt"
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

// Блокировка рекламы стоит после списков раздельного туннеля, локальной сети, правил
// пользователя и сервера, но до общих правил региона. Это и для маршрутов, и для DNS.
func TestBlockAdsAfterSplitTunnelLists(t *testing.T) {
	defer func(old bool) { isWindows = old }(isWindows)
	isWindows = false
	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.BlockAds = true
	hopt.Region = "ru"
	hopt.SplitTunnelDir = filepath.Join(t.TempDir(), "split")
	hopt.Rules = []Rule{{Enabled: true, Outbound: Outbound_direct, DomainSuffixes: []string{"user-direct.example"}}}
	o := buildTestConfig(t, testSubscription, hopt)

	adsRoute := routeIdx(o, func(r option.DefaultRule) bool {
		return slices.Contains(r.RuleSet, "geosite-ads") && r.Action == "reject"
	})
	if adsRoute < 0 {
		t.Fatal("нет правила блокировки рекламы в маршрутах")
	}
	before := map[string]func(option.DefaultRule) bool{
		"через VPN":    func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) },
		"мимо VPN":     func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitBypassTag) },
		"локальная":    func(r option.DefaultRule) bool { return r.IPIsPrivate },
		"пользователь": func(r option.DefaultRule) bool { return slices.Contains(r.DomainSuffix, "user-direct.example") },
		"сервер":       func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "server-ru-ip") },
		"только VPN":   func(r option.DefaultRule) bool { return slices.Contains(r.Domain, "only-vpn.example") },
	}
	for name, match := range before {
		if i := routeIdx(o, match); i < 0 || i > adsRoute {
			t.Errorf("маршрут %q (%d) должен стоять выше блокировки рекламы (%d)", name, i, adsRoute)
		}
	}
	after := map[string]func(option.DefaultRule) bool{
		"домены региона": func(r option.DefaultRule) bool { return slices.Contains(r.DomainSuffix, ".ru") },
		"geoip региона":  func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "geoip-ru") },
	}
	for name, match := range after {
		if i := routeIdx(o, match); i < adsRoute {
			t.Errorf("маршрут %q (%d) должен стоять ниже блокировки рекламы (%d)", name, i, adsRoute)
		}
	}
	// Первое правило маршрута ICMP остаётся выше всего.
	if icmp := routeIdx(o, isICMPRule); icmp < 0 || icmp > routeIdx(o, before["через VPN"]) {
		t.Errorf("ICMP (%d) должен стоять выше списков", icmp)
	}

	adsDNS := dnsIdx(o, func(r option.DefaultDNSRule) bool {
		return slices.Contains(r.RuleSet, "geosite-ads")
	})
	if adsDNS < 0 {
		t.Fatal("нет DNS-правила блокировки рекламы")
	}
	beforeDNS := map[string]func(option.DefaultDNSRule) bool{
		"сайты через VPN": func(r option.DefaultDNSRule) bool {
			return slices.Contains(r.RuleSet, splitViaDomainsTag) && r.RouteOptions.Server == DNSMultiRemoteTag
		},
		"сайты мимо VPN": func(r option.DefaultDNSRule) bool {
			return slices.Contains(r.RuleSet, splitBypassDomainsTag) && r.RouteOptions.Server == DNSMultiDirectTag
		},
		"пользователь": func(r option.DefaultDNSRule) bool {
			return slices.Contains(r.DomainSuffix, "user-direct.example") && r.RouteOptions.Server == DNSMultiDirectTag
		},
		"сервер": func(r option.DefaultDNSRule) bool { return slices.Contains(r.RuleSet, "server-ru-domains") },
	}
	for name, match := range beforeDNS {
		if i := dnsIdx(o, match); i < 0 || i > adsDNS {
			t.Errorf("DNS %q (%d) должен стоять выше блокировки рекламы (%d)", name, i, adsDNS)
		}
	}
	for name, match := range map[string]func(option.DefaultDNSRule) bool{
		"домены региона":  func(r option.DefaultDNSRule) bool { return slices.Contains(r.DomainSuffix, ".ru") },
		"geosite региона": func(r option.DefaultDNSRule) bool { return slices.Contains(r.RuleSet, "geosite-ru") },
	} {
		if i := dnsIdx(o, match); i < adsDNS {
			t.Errorf("DNS %q (%d) должен стоять ниже блокировки рекламы (%d)", name, i, adsDNS)
		}
	}
	t.Logf("маршруты:\n%s", describeRoute(o))
	t.Logf("DNS:\n%s", describeDNS(o))
}

func describeRoute(o *option.Options) string {
	var s string
	for i, r := range o.Route.Rules {
		d := r.DefaultOptions
		s += fmt.Sprintf("%2d action=%s net=%v sets=%v domain=%v suffix=%v cidr=%v private=%v out=%s\n",
			i, d.Action, d.Network, d.RuleSet, d.Domain, d.DomainSuffix, d.IPCIDR, d.IPIsPrivate, d.RouteOptions.Outbound)
	}
	return s
}

func describeDNS(o *option.Options) string {
	var s string
	for i, r := range o.DNS.Rules {
		d := r.DefaultOptions
		s += fmt.Sprintf("%2d action=%s sets=%v suffix=%v server=%s\n", i, d.Action, d.RuleSet, d.DomainSuffix, d.RouteOptions.Server)
	}
	return s
}

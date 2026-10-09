package config

import (
	"encoding/json"
	"regexp"
	"slices"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// Подписка в том виде, как её отдаёт наш PasarGuard (шаблон singbox/client-template.json
// из vpn-server), ключи вымышленные.
const testSubscription = `{
  "log": {"level": "warn"},
  "dns": {
    "servers": [
      {"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "proxy"},
      {"type": "udp", "tag": "dns-local", "server": "77.88.8.8"}
    ],
    "rules": [{"rule_set": ["ru-inside", "ru-domains"], "server": "dns-local"}],
    "final": "dns-remote",
    "strategy": "ipv4_only"
  },
  "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": true}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["Best Latency", "NL"]},
    {"type": "urltest", "tag": "Best Latency", "outbounds": ["NL"]},
    {"type": "vless", "tag": "NL", "server": "203.0.113.10", "server_port": 443,
     "uuid": "00000000-0000-4000-8000-000000000000", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "vpn.example.com",
             "utls": {"enabled": true, "fingerprint": "chrome"},
             "reality": {"enabled": true, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short_id": ""}}},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"inbound": "tun-in", "action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"},
      {"rule_set": ["ru-inside", "ru-domains", "ru-ip"], "outbound": "direct"},
      {"domain_suffix": ["ads.example"], "action": "reject"},
      {"domain": ["only-vpn.example"], "outbound": "Best Latency"}
    ],
    "rule_set": [
      {"type": "remote", "tag": "ru-inside", "format": "binary", "url": "https://example.com/inside.srs", "update_interval": "1d"},
      {"type": "remote", "tag": "ru-domains", "format": "binary", "url": "https://example.com/domains.srs", "update_interval": "1d"},
      {"type": "remote", "tag": "ru-ip", "format": "binary", "url": "https://example.com/ip.srs", "update_interval": "1d"}
    ],
    "final": "proxy",
    "auto_detect_interface": true
  }
}`

func buildTestConfig(t *testing.T, subscription string, hopt *HiddifyOptions) *option.Options {
	t.Helper()
	ctx := libbox.BaseContext(nil)
	parsed, err := ParseConfig(ctx, &ReadOptions{Content: subscription}, false, nil, false)
	if err != nil {
		t.Fatalf("разбор подписки: %v", err)
	}
	// Как в приложении: разобранный профиль сохраняется в JSON, потом читается заново.
	stored, err := parsed.MarshalJSONContext(ctx)
	if err != nil {
		t.Fatalf("сохранение профиля: %v", err)
	}
	built, err := BuildConfigJson(ctx, hopt, &ReadOptions{Content: string(stored)})
	if err != nil {
		t.Fatalf("сборка конфига: %v", err)
	}
	var out option.Options
	if err := out.UnmarshalJSONContext(ctx, built); err != nil {
		t.Fatalf("чтение итогового конфига: %v", err)
	}
	return &out
}

func findRouteRule(o *option.Options, match func(option.DefaultRule) bool) *option.DefaultRule {
	for _, r := range o.Route.Rules {
		if match(r.DefaultOptions) {
			return &r.DefaultOptions
		}
	}
	return nil
}

func ruleSetTags(o *option.Options) []string {
	var tags []string
	for _, rs := range o.Route.RuleSet {
		tags = append(tags, rs.Tag)
	}
	return tags
}

func TestServerRulesFromSubscription(t *testing.T) {
	o := buildTestConfig(t, testSubscription, DefaultHiddifyOptions())

	for _, tag := range []string{"server-ru-inside", "server-ru-domains", "server-ru-ip"} {
		if !slices.Contains(ruleSetTags(o), tag) {
			t.Errorf("нет набора правил %s, есть %v", tag, ruleSetTags(o))
		}
	}
	ru := findRouteRule(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "server-ru-ip") })
	if ru == nil || ru.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("российское должно идти напрямую: %+v", ru)
	}
	private := findRouteRule(o, func(r option.DefaultRule) bool { return r.IPIsPrivate })
	if private == nil || private.RouteOptions.Outbound != OutboundDirectTag {
		t.Errorf("локальная сеть должна идти напрямую: %+v", private)
	}
	ads := findRouteRule(o, func(r option.DefaultRule) bool { return slices.Contains(r.DomainSuffix, "ads.example") })
	if ads == nil || ads.Action != "reject" {
		t.Errorf("реклама должна блокироваться: %+v", ads)
	}
	vpn := findRouteRule(o, func(r option.DefaultRule) bool { return slices.Contains(r.Domain, "only-vpn.example") })
	if vpn == nil || vpn.RouteOptions.Outbound != OutboundMainDetour {
		t.Errorf("выход urltest с сервера должен стать выбором приложения: %+v", vpn)
	}
	for _, r := range o.Route.Rules {
		if slices.Contains(r.DefaultOptions.Inbound, "tun-in") {
			t.Errorf("правило с inbound сервера попало в конфиг: %+v", r.DefaultOptions)
		}
	}

	foundDNS := false
	for _, r := range o.DNS.Rules {
		if slices.Contains(r.DefaultOptions.RuleSet, "server-ru-domains") {
			foundDNS = true
			if r.DefaultOptions.RouteOptions.Server != DNSMultiDirectTag {
				t.Errorf("российские домены должны резолвиться напрямую: %+v", r.DefaultOptions)
			}
		}
	}
	if !foundDNS {
		t.Error("нет DNS-правила для российских доменов")
	}
	if o.Route.FindProcess {
		t.Error("без правил по программам определение процесса не нужно")
	}
}

func TestIgnoreServerRules(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.IgnoreServerRules = true
	o := buildTestConfig(t, testSubscription, hopt)
	for _, tag := range ruleSetTags(o) {
		if len(tag) > len(serverRuleSetPrefix) && tag[:len(serverRuleSetPrefix)] == serverRuleSetPrefix {
			t.Errorf("правила сервера выключены, но набор %s есть", tag)
		}
	}
}

func TestUserRules(t *testing.T) {
	defer func(old bool) { isWindows = old }(isWindows)
	isWindows = false
	hopt := DefaultHiddifyOptions()
	hopt.Rules = []Rule{
		{Enabled: true, ListOrder: 2, Outbound: Outbound_direct, ProcessNames: []string{"Telegram.exe"}},
		{Enabled: true, ListOrder: 1, Outbound: Outbound_block, DomainSuffixes: []string{"tracker.example"}},
		{Enabled: true, ListOrder: 3, Outbound: Outbound_proxy, RuleSets: []string{"geosite:ru", "https://example.com/my.srs", "мусор"}, PortRanges: []string{"443", "1000:2000", "3000-4000", "плохо"}},
		{Enabled: false, Outbound: Outbound_direct, ProcessNames: []string{"disabled.exe"}},
		{Enabled: true, Outbound: Outbound_direct}, // без условий: пропускается
	}
	o := buildTestConfig(t, testSubscription, hopt)

	if !o.Route.FindProcess {
		t.Error("правило по программе требует find_process")
	}
	tg := findRouteRule(o, func(r option.DefaultRule) bool { return slices.Contains(r.ProcessName, "Telegram.exe") })
	if tg == nil || tg.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("Telegram.exe должен идти напрямую: %+v", tg)
	}
	if findRouteRule(o, func(r option.DefaultRule) bool { return slices.Contains(r.ProcessName, "disabled.exe") }) != nil {
		t.Error("выключенное правило попало в конфиг")
	}

	// Пользовательские правила выше серверных, порядок по list_order.
	idx := func(match func(option.DefaultRule) bool) int {
		for i, r := range o.Route.Rules {
			if match(r.DefaultOptions) {
				return i
			}
		}
		return -1
	}
	block := idx(func(r option.DefaultRule) bool { return slices.Contains(r.DomainSuffix, "tracker.example") })
	telegram := idx(func(r option.DefaultRule) bool { return slices.Contains(r.ProcessName, "Telegram.exe") })
	server := idx(func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "server-ru-ip") })
	if !(block >= 0 && block < telegram && telegram < server) {
		t.Errorf("порядок правил: блок=%d, telegram=%d, сервер=%d", block, telegram, server)
	}

	sets := ruleSetTags(o)
	if !slices.Contains(sets, "user-geosite-ru") {
		t.Errorf("нет набора user-geosite-ru: %v", sets)
	}
	ports := findRouteRule(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "user-geosite-ru") })
	if ports == nil || !slices.Contains(ports.Port, uint16(443)) || !slices.Contains(ports.PortRange, "1000:2000") || !slices.Contains(ports.PortRange, "3000:4000") || len(ports.PortRange) != 2 {
		t.Errorf("порты разобраны неверно: %+v", ports)
	}
	if len(ports.RuleSet) != 2 {
		t.Errorf("ожидалось 2 набора (geosite и ссылка, мусор пропущен): %v", ports.RuleSet)
	}

	dnsTelegram := false
	for _, r := range o.DNS.Rules {
		if slices.Contains(r.DefaultOptions.ProcessName, "Telegram.exe") {
			dnsTelegram = r.DefaultOptions.RouteOptions.Server == DNSMultiDirectTag
		}
	}
	if !dnsTelegram {
		t.Error("DNS программы мимо VPN должен идти напрямую")
	}
}

// Подписка со старым форматом DNS, который это ядро может не принять:
// профиль всё равно добавляется, только без правил сервера.
func TestBrokenServerRulesFallBack(t *testing.T) {
	var sub map[string]any
	if err := json.Unmarshal([]byte(testSubscription), &sub); err != nil {
		t.Fatal(err)
	}
	sub["dns"] = map[string]any{"servers": []any{map[string]any{"type": "no-such-type", "tag": "x"}}}
	b, _ := json.Marshal(sub)
	parsed, err := ParseConfig(libbox.BaseContext(nil), &ReadOptions{Content: string(b)}, false, nil, false)
	if err != nil {
		t.Fatalf("профиль с непонятным DNS должен добавляться: %v", err)
	}
	if len(parsed.Outbounds) == 0 {
		t.Error("серверы потерялись")
	}
	if parsed.DNS != nil && len(parsed.DNS.Servers) > 0 {
		t.Error("непонятный DNS должен быть отброшен")
	}
}

func TestIPv4OnlyMode(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.EnableTun = true
	hopt.IPv6Mode = option.DomainStrategy(C.DomainStrategyIPv4Only)
	o := buildTestConfig(t, testSubscription, hopt)

	tuns := 0
	for _, in := range o.Inbounds {
		tun, ok := in.Options.(*option.TunInboundOptions)
		if !ok {
			continue
		}
		tuns++
		for _, p := range tun.Address {
			if p.Addr().Is6() {
				t.Errorf("IPv6 выключен, а у туннеля адрес %s", p)
			}
		}
	}
	if tuns != 1 {
		t.Fatalf("ожидался один туннель, найдено %d", tuns)
	}
	last := o.DNS.Rules[len(o.DNS.Rules)-1].DefaultOptions
	if last.RouteOptions.Strategy != option.DomainStrategy(C.DomainStrategyIPv4Only) {
		t.Errorf("DNS должен отдавать только IPv4: %v", last.RouteOptions.Strategy)
	}
	if hopt.RemoteDnsDomainStrategy != option.DomainStrategy(C.DomainStrategyAsIS) {
		t.Error("BuildConfig не должен менять настройки вызывающего")
	}
}

func TestProcessNamesOnWindows(t *testing.T) {
	defer func(old bool) { isWindows = old }(isWindows)
	isWindows = true
	hopt := DefaultHiddifyOptions()
	hopt.Rules = []Rule{{Enabled: true, Outbound: Outbound_direct, ProcessNames: []string{"Steam.exe", "League of Legends.exe"}}}
	o := buildTestConfig(t, testSubscription, hopt)

	rule := findRouteRule(o, func(r option.DefaultRule) bool { return len(r.ProcessPathRegex) == 2 })
	if rule == nil {
		t.Fatal("на Windows имена программ должны стать process_path_regex")
	}
	if len(rule.ProcessName) != 0 || !o.Route.FindProcess {
		t.Errorf("process_name не нужен, find_process нужен: %+v", rule)
	}
	matches := func(path string) bool {
		for _, re := range rule.ProcessPathRegex {
			if regexp.MustCompile(re).MatchString(path) {
				return true
			}
		}
		return false
	}
	for path, want := range map[string]bool{
		`C:\Program Files (x86)\Steam\steam.exe`:                true,
		`C:\Riot Games\League of Legends\League of Legends.exe`: true,
		`C:\Program Files (x86)\Steam\notsteam.exe`:             false,
		`C:\Program Files (x86)\Steam\steam.exe.bak`:            false,
		`C:\Riot Games\League of Legends\League ofXLegends.exe`: false,
	} {
		if got := matches(path); got != want {
			t.Errorf("%s: совпадение %v, ожидалось %v", path, got, want)
		}
	}
}

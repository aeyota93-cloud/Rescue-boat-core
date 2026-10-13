package config

import (
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// Общий пример с приложением (docs/rescue-servers-v2.md): ключ считается одинаково.
func TestServerKey(t *testing.T) {
	for tag, want := range map[string]string{
		"NL запасной": "b286f8a79b8f",
		"NL":          "4334ffcf7813",
	} {
		if got := ServerKey(tag); got != want {
			t.Errorf("ServerKey(%q) = %q, ждали %q", tag, got, want)
		}
	}
}

func TestSplitTunnelRules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "split")
	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.SplitTunnelDir = dir
	o := buildTestConfig(t, testSubscription, hopt)

	for _, name := range []string{"via-vpn.json", "via-domains.json", "bypass-vpn.json", "bypass-domains.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("ядро должно создать пустой %s: %v", name, err)
		}
	}

	idx := func(match func(option.DefaultRule) bool) int {
		for i, r := range o.Route.Rules {
			if match(r.DefaultOptions) {
				return i
			}
		}
		return -1
	}
	via := idx(func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) })
	bypass := idx(func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitBypassTag) })
	lan := idx(func(r option.DefaultRule) bool { return r.IPIsPrivate })
	server := idx(func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, "server-ru-ip") })
	if !(via >= 0 && via < bypass && bypass < lan && lan < server) {
		t.Fatalf("порядок: через VPN=%d, мимо=%d, локальная сеть=%d, сервер=%d", via, bypass, lan, server)
	}
	if o.Route.Rules[via].DefaultOptions.RouteOptions.Outbound != OutboundMainDetour ||
		o.Route.Rules[bypass].DefaultOptions.RouteOptions.Outbound != OutboundDirectTag {
		t.Error("списки ведут не туда")
	}

	directDNS := false
	for _, r := range o.DNS.Rules {
		if slices.Contains(r.DefaultOptions.RuleSet, splitBypassDomainsTag) {
			directDNS = r.DefaultOptions.RouteOptions.Server == DNSMultiDirectTag
		}
	}
	if !directDNS {
		t.Error("сайты из списка «мимо VPN» должны резолвиться напрямую")
	}
}

// Формат, который пишет приложение (lib/features/split_tunnel): sing-box должен его читать.
func TestSplitTunnelFileFormat(t *testing.T) {
	content := []byte(`{"version": 3, "rules": [
	  {"process_path_regex": ["(?i)(^|[\\\\/])steam\\.exe$"]},
	  {"domain_suffix": ["example.com"]},
	  {"ip_cidr": ["10.0.0.0/8", "8.8.8.8/32"]}
	]}`)
	set, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
	if err != nil {
		t.Fatalf("sing-box не читает файл приложения: %v", err)
	}
	if len(set.Options.Rules) != 3 {
		t.Errorf("ожидалось 3 правила, прочитано %d", len(set.Options.Rules))
	}
	empty, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(emptyRuleSet))
	if err != nil || len(empty.Options.Rules) != 0 {
		t.Errorf("пустой набор: %v", err)
	}
}

// sing-box приклеивает к рабочей папке любой путь без «/» в начале, в том числе «C:\...».
// Путь из набора правил должен находиться так, как его откроет sing-box: Join(рабочая папка, путь).
func TestSplitTunnelRuleSetPathFromWorkingDir(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	dir := filepath.Join(work, "split")
	hopt := DefaultHiddifyOptions()
	hopt.SplitTunnelDir = dir
	o := buildTestConfig(t, testSubscription, hopt)

	found := 0
	for _, rs := range o.Route.RuleSet {
		p := rs.LocalOptions.Path
		if p == "" {
			continue
		}
		found++
		if filepath.IsAbs(p) {
			t.Errorf("путь набора правил %q абсолютный — sing-box склеит его с рабочей папкой", p)
		}
		if _, err := os.Stat(filepath.Join(work, p)); err != nil {
			t.Errorf("sing-box не найдёт %q: %v", p, err)
		}
	}
	if found != 4 {
		t.Fatalf("ожидалось 4 локальных набора правил, найдено %d", found)
	}
}

// Три сервера, как отдаёт наш PasarGuard (docs/rescue-servers-v2.md): основной и игровой
// Hysteria2 в JSON, запасной XHTTP — из `<подписка>/links`.
func threeServerSubscription(t *testing.T) string {
	t.Helper()
	var obj map[string]interface{}
	if err := stdjson.Unmarshal([]byte(subscriptionWithLinks(t, testRescueLinks)), &obj); err != nil {
		t.Fatal(err)
	}
	obj["outbounds"] = append(obj["outbounds"].([]interface{}), map[string]interface{}{
		"type": "hysteria2", "tag": "NL игры", "server": "203.0.113.10", "server_port": 8443,
		"password": "secret", "tls": map[string]interface{}{"enabled": true, "server_name": "games.example.com"},
	})
	b, _ := stdjson.Marshal(obj)
	return string(b)
}

func viaServerSets(o *option.Options) []string {
	var tags []string
	for _, rs := range o.Route.RuleSet {
		if strings.HasPrefix(rs.Tag, splitViaServerPrefix) {
			tags = append(tags, rs.Tag)
		}
	}
	return tags
}

func TestSplitTunnelServerRules(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	dir := filepath.Join(work, "split")
	// Файл сервера, которого нет в профиле: ядро его не трогает.
	stranger := filepath.Join(dir, "via-server-000000000000.json")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stranger, []byte(`{"version": 3, "rules": [{"domain": ["x.example"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Уже закреплённое за запасным приложение записало раньше: файл не перезаписывается.
	backup := filepath.Join(dir, "via-server-"+ServerKey("NL запасной")+".json")
	pinned := []byte(`{"version": 3, "rules": [{"domain_suffix": ["game.example"]}]}`)
	if err := os.WriteFile(backup, pinned, 0o644); err != nil {
		t.Fatal(err)
	}

	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.SplitTunnelDir = dir
	o := buildTestConfig(t, threeServerSubscription(t), hopt)

	// Порядок — как в select (куда встаёт запасной из ссылок, решает rescue_links.go), группы
	// lowest и balance — не серверы, Hysteria2 — сервер.
	var servers []string
	for _, out := range o.Outbounds {
		if out.Tag == OutboundSelectTag {
			for _, tag := range out.Options.(*option.SelectorOutboundOptions).Outbounds {
				if tag != OutboundURLTestTag && tag != OutboundRoundRobinTag {
					servers = append(servers, tag)
				}
			}
		}
	}
	sorted := slices.Sorted(slices.Values(servers))
	if !slices.Equal(sorted, []string{"NL", "NL запасной", "NL игры"}) {
		t.Fatalf("в select не те серверы: %v", servers)
	}
	if got := selectServers(o); !slices.Equal(got, servers) {
		t.Fatalf("серверы из select: %v, ждали %v", got, servers)
	}
	// По одному набору на сервер, по порядку select; группы (lowest, balance) не попадают.
	var want []string
	for _, tag := range servers {
		want = append(want, splitViaServerPrefix+ServerKey(tag))
	}
	if got := viaServerSets(o); !slices.Equal(got, want) {
		t.Fatalf("наборы серверов: %v, ждали %v", got, want)
	}
	for _, rs := range o.Route.RuleSet {
		if !strings.HasPrefix(rs.Tag, splitViaServerPrefix) {
			continue
		}
		p := rs.LocalOptions.Path
		if filepath.IsAbs(p) {
			t.Errorf("путь %q абсолютный — sing-box склеит его с рабочей папкой", p)
		}
		if _, err := os.Stat(filepath.Join(work, p)); err != nil {
			t.Errorf("sing-box не найдёт %q: %v", p, err)
		}
		if filepath.Base(p) != "via-server-"+strings.TrimPrefix(rs.Tag, splitViaServerPrefix)+".json" {
			t.Errorf("набор %s читает не свой файл %q", rs.Tag, p)
		}
	}
	if b, _ := os.ReadFile(backup); string(b) != string(pinned) {
		t.Errorf("файл запасного перезаписан: %s", b)
	}
	if b, _ := os.ReadFile(stranger); !strings.Contains(string(b), "x.example") {
		t.Errorf("файл чужого сервера тронут: %s", b)
	}

	// Правила серверов — по порядку, каждое на свой выход, все выше «через VPN».
	via := routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) })
	bypass := routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitBypassTag) })
	prev := -1
	for i, setTag := range want {
		idx := routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, setTag) })
		if idx < 0 || idx <= prev || idx >= via {
			t.Fatalf("правило %s на месте %d (предыдущее %d, «через VPN» %d)", servers[i], idx, prev, via)
		}
		if out := o.Route.Rules[idx].DefaultOptions.RouteOptions.Outbound; out != servers[i] {
			t.Errorf("закреплённое за %q идёт на %q", servers[i], out)
		}
		prev = idx
	}
	if !(via < bypass) {
		t.Errorf("порядок: через VPN=%d, мимо=%d", via, bypass)
	}
	if err := libbox.CheckConfigOptions(o); err != nil {
		t.Fatalf("sing-box не принял конфиг: %v", err)
	}
}

// Один сервер в профиле или нет папки списков — наборов серверов нет, всё как раньше.
func TestSplitTunnelServerRulesAsBefore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "split")
	hopt := DefaultHiddifyOptions()
	hopt.SplitTunnelDir = dir
	o := buildTestConfig(t, testSubscription, hopt)
	if got := viaServerSets(o); len(got) != 0 {
		t.Errorf("один сервер, а наборы серверов есть: %v", got)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "via-server-*.json")); len(m) != 0 {
		t.Errorf("один сервер, а файлы серверов созданы: %v", m)
	}
	if len(o.Route.RuleSet) == 0 || routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) }) < 0 {
		t.Error("списки раздельного туннеля пропали")
	}

	o = buildTestConfig(t, threeServerSubscription(t), DefaultHiddifyOptions())
	if got := viaServerSets(o); len(got) != 0 {
		t.Errorf("без папки списков наборы серверов есть: %v", got)
	}
	if routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) }) >= 0 {
		t.Error("без папки списков правило «через VPN» есть")
	}
	if err := libbox.CheckConfigOptions(o); err != nil {
		t.Fatalf("sing-box не принял конфиг: %v", err)
	}
}

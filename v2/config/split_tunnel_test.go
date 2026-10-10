package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestSplitTunnelRules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "split")
	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.SplitTunnelDir = dir
	o := buildTestConfig(t, testSubscription, hopt)

	for _, name := range []string{"via-vpn.json", "bypass-vpn.json", "bypass-domains.json"} {
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
	if found != 3 {
		t.Fatalf("ожидалось 3 локальных набора правил, найдено %d", found)
	}
}

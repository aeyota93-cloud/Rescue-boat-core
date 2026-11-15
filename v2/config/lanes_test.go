package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func lanesTestConfig(t *testing.T) (*option.Options, string) {
	t.Helper()
	work := t.TempDir()
	t.Chdir(work)
	dir := filepath.Join(work, "split")
	hopt := DefaultHiddifyOptions()
	hopt.BypassLAN = true
	hopt.SplitTunnelDir = dir
	return buildTestConfig(t, threeServerSubscription(t), hopt), dir
}

func ruleOutbound(r option.Rule) string {
	if r.Type == C.RuleTypeLogical {
		return r.LogicalOptions.RouteOptions.Outbound
	}
	return r.DefaultOptions.RouteOptions.Outbound
}

// isLaneRule — правило «X и запись группы n» (или правило группы n в конце).
func laneGroupOf(r option.Rule) (int, bool) {
	sets := r.DefaultOptions.RuleSet
	if r.Type == C.RuleTypeLogical {
		inner := r.LogicalOptions.Rules
		if len(inner) != 2 || r.LogicalOptions.Mode != C.LogicalTypeAnd {
			return 0, false
		}
		sets = inner[1].DefaultOptions.RuleSet
	}
	for n := 0; n < LaneCount; n++ {
		if slices.Equal(sets, []string{laneGroupSet(n)}) {
			return n, true
		}
	}
	return 0, false
}

// Полосы: селекторы из копий серверов select, наборы групп, файлы групп.
func TestLanesOutbounds(t *testing.T) {
	o, dir := lanesTestConfig(t)
	servers := selectServers(o)
	if len(servers) != 3 {
		t.Fatalf("серверы select: %v", servers)
	}
	outs := map[string]option.Outbound{}
	for _, out := range o.Outbounds {
		outs[out.Tag] = out
	}
	sets := map[string]bool{}
	for _, rs := range o.Route.RuleSet {
		sets[rs.Tag] = true
	}
	for n := 0; n < LaneCount; n++ {
		lane, ok := outs[LaneTag(n)]
		if !ok {
			t.Fatalf("нет селектора полосы %d", n)
		}
		var want []string
		for _, tag := range servers {
			want = append(want, LaneCopyTag(tag, n))
		}
		if got := lane.Options.(*option.SelectorOutboundOptions).Outbounds; !slices.Equal(got, want) {
			t.Fatalf("полоса %d: %v, ждали %v", n, got, want)
		}
		for i, tag := range want {
			if cp, ok := outs[tag]; !ok || cp.Type != outs[servers[i]].Type || !strings.Contains(tag, "§hide§") {
				t.Fatalf("копия %q: есть=%v", tag, ok)
			}
		}
		if !sets[laneGroupSet(n)] {
			t.Errorf("нет набора группы %d", n)
		}
		if _, err := os.Stat(filepath.Join(dir, LaneGroupFile(n))); err != nil {
			t.Errorf("ядро должно создать пустой файл группы %d: %v", n, err)
		}
	}
	// Копии не попадают в выбор серверов, «Авто» и сторожа.
	if got := selectServers(o); !slices.Equal(got, servers) {
		t.Errorf("серверы select изменились: %v", got)
	}
	for _, out := range o.Outbounds {
		var members []string
		switch opts := out.Options.(type) {
		case *option.SelectorOutboundOptions:
			if out.Tag == OutboundSelectTag {
				members = opts.Outbounds
			}
		case *option.BalancerOutboundOptions:
			members = opts.Outbounds
		}
		for _, tag := range members {
			if IsLaneTag(tag) {
				t.Errorf("в %s попала полоса %q", out.Tag, tag)
			}
		}
	}
	if err := libbox.CheckConfigOptions(o); err != nil {
		t.Fatalf("sing-box не принял конфиг: %v", err)
	}
}

// Одно правило на всё: перед каждым правилом, которое ведёт в select или на сервер, — то же
// правило для каждой группы на её полосу; остальные правила (мимо VPN и т. п.) без полос;
// в конце — «всё остальное» для каждой группы.
func TestLanesWrapEveryVPNRule(t *testing.T) {
	o, _ := lanesTestConfig(t)
	servers := selectServers(o)
	isServer := map[string]bool{}
	for _, s := range servers {
		isServer[s] = true
	}
	rules := o.Route.Rules
	var plain []option.Rule // правила без полос — как без групп
	for _, r := range rules {
		if _, ok := laneGroupOf(r); !ok {
			plain = append(plain, r)
		}
	}
	vpnRules := 0
	for i := 0; i < len(rules); {
		if _, ok := laneGroupOf(rules[i]); ok {
			// Блок полос: LaneCount правил подряд, затем исходное правило (или конец — final).
			end := i + LaneCount
			if end > len(rules) {
				t.Fatalf("блок полос на %d обрезан", i)
			}
			var orig option.Rule
			tail := end == len(rules)
			if !tail {
				orig = rules[end]
			}
			for n := 0; n < LaneCount; n++ {
				r := rules[i+n]
				if g, _ := laneGroupOf(r); g != n {
					t.Fatalf("правило %d: группа %d, ждали %d", i+n, g, n)
				}
				base := OutboundSelectTag
				if !tail {
					base = ruleOutbound(orig)
					// Условие — то же, что у исходного правила.
					inner := r.LogicalOptions.Rules[0]
					if inner.Type != orig.Type ||
						!slices.Equal(inner.DefaultOptions.RuleSet, orig.DefaultOptions.RuleSet) ||
						inner.DefaultOptions.IPIsPrivate != orig.DefaultOptions.IPIsPrivate {
						t.Fatalf("правило %d: условие не совпадает с исходным", i+n)
					}
				}
				want := LaneTag(n)
				if base != OutboundSelectTag {
					want = LaneCopyTag(base, n)
				}
				if got := ruleOutbound(r); got != want {
					t.Fatalf("правило %d ведёт на %q, ждали %q", i+n, got, want)
				}
			}
			if !tail {
				vpnRules++
			}
			i = end + 1
			continue
		}
		if out := ruleOutbound(rules[i]); out == OutboundSelectTag || isServer[out] {
			t.Fatalf("правило %d ведёт в VPN (%q), но полос перед ним нет", i, out)
		}
		i++
	}
	// Закреплённые за серверами (3) и «через VPN» (1) — как минимум.
	if vpnRules < 4 {
		t.Errorf("обёрнуто правил VPN: %d", vpnRules)
	}
	last := rules[len(rules)-LaneCount:]
	for n, r := range last {
		if g, ok := laneGroupOf(r); !ok || g != n || r.Type != C.RuleTypeDefault || ruleOutbound(r) != LaneTag(n) {
			t.Fatalf("в конце нет правила группы %d", n)
		}
	}
	if o.Route.Final != OutboundSelectTag {
		t.Errorf("final: %q", o.Route.Final)
	}
	// Без групп порядок правил прежний: «через VPN» выше «мимо», «мимо» выше локальной сети.
	idx := func(set string) int {
		for i, r := range plain {
			if slices.Contains(r.DefaultOptions.RuleSet, set) {
				return i
			}
		}
		return -1
	}
	if !(idx(splitViaTag) < idx(splitBypassTag)) {
		t.Error("порядок списков сломан")
	}
	if err := libbox.CheckConfigOptions(o); err != nil {
		t.Fatalf("sing-box не принял конфиг: %v", err)
	}
}

// Без папки списков полос нет.
func TestLanesNeedSplitDir(t *testing.T) {
	o := buildTestConfig(t, threeServerSubscription(t), DefaultHiddifyOptions())
	for _, out := range o.Outbounds {
		if IsLaneTag(out.Tag) {
			t.Fatalf("без папки списков есть полоса %q", out.Tag)
		}
	}
	for _, r := range o.Route.Rules {
		if _, ok := laneGroupOf(r); ok {
			t.Fatal("без папки списков есть правило группы")
		}
	}
}

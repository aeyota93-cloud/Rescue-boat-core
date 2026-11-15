package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// Полосы групп: на каждую полосу — селектор из копий серверов select, правило по файлу
// via-lane-<n>.json между закреплёнными за сервером и общим «через VPN».
func TestLanes(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	dir := filepath.Join(work, "split")
	hopt := DefaultHiddifyOptions()
	hopt.SplitTunnelDir = dir
	o := buildTestConfig(t, threeServerSubscription(t), hopt)

	servers := selectServers(o)
	if len(servers) != 3 {
		t.Fatalf("серверы select: %v", servers)
	}
	outs := map[string]option.Outbound{}
	for _, out := range o.Outbounds {
		outs[out.Tag] = out
	}

	via := routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, splitViaTag) })
	lastServer := -1
	for _, tag := range servers {
		set := splitViaServerPrefix + ServerKey(tag)
		lastServer = max(lastServer, routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, set) }))
	}
	prev := lastServer
	for n := 0; n < LaneCount; n++ {
		lane, ok := outs[LaneTag(n)]
		if !ok {
			t.Fatalf("нет селектора полосы %d", n)
		}
		sel := lane.Options.(*option.SelectorOutboundOptions)
		var want []string
		for _, tag := range servers {
			want = append(want, LaneCopyTag(tag, n))
		}
		if !slices.Equal(sel.Outbounds, want) {
			t.Fatalf("полоса %d: %v, ждали %v", n, sel.Outbounds, want)
		}
		for i, tag := range want {
			cp, ok := outs[tag]
			if !ok || cp.Type != outs[servers[i]].Type {
				t.Fatalf("копия %q: есть=%v, тип %q, у сервера %q", tag, ok, cp.Type, outs[servers[i]].Type)
			}
			if !strings.Contains(tag, "§hide§") || !IsLaneTag(tag) {
				t.Errorf("копия %q не скрыта или не опознаётся как полоса", tag)
			}
		}
		set := fmt.Sprintf("%s%d", splitViaLanePrefix, n)
		idx := routeIdx(o, func(r option.DefaultRule) bool { return slices.Contains(r.RuleSet, set) })
		if idx <= prev || idx >= via {
			t.Fatalf("правило полосы %d на месте %d (предыдущее %d, «через VPN» %d)", n, idx, prev, via)
		}
		if got := o.Route.Rules[idx].DefaultOptions.RouteOptions.Outbound; got != LaneTag(n) {
			t.Errorf("полоса %d ведёт на %q", n, got)
		}
		prev = idx
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("via-lane-%d.json", n))); err != nil {
			t.Errorf("ядро должно создать пустой файл полосы %d: %v", n, err)
		}
	}
	// Копии не попадают в выбор серверов, «Авто» и сторожа.
	if got := selectServers(o); !slices.Equal(got, servers) {
		t.Errorf("серверы select изменились: %v", got)
	}
	for _, out := range o.Outbounds {
		if sel, ok := out.Options.(*option.SelectorOutboundOptions); ok && out.Tag == OutboundSelectTag {
			for _, tag := range sel.Outbounds {
				if IsLaneTag(tag) {
					t.Errorf("в select попала полоса %q", tag)
				}
			}
		}
		if b, ok := out.Options.(*option.BalancerOutboundOptions); ok {
			for _, tag := range b.Outbounds {
				if IsLaneTag(tag) {
					t.Errorf("в %s попала полоса %q", out.Tag, tag)
				}
			}
		}
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
}

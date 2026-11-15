package config

// Полосы групп «Шлюпки спасения».
//
// Через VPN всё шло одним соединением с сервером (у gRPC — одно HTTP/2-соединение на выход).
// Когда что-то качается, пакеты Discord или игры ждали в той же очереди: пинг до секунд.
// Полоса — отдельный выход к тому же серверу, то есть своё соединение.
//
// Одно правило на всё: запись группы идёт туда же, куда шла бы без групп; если туда — VPN-сервер,
// то соединением своей группы. Приложение пишет все записи группы n в group-<n>.json; ядро не
// разбирает, «через VPN» запись, «Авто» или закреплена за сервером. После сборки всех правил
// applyLanes проходит по ним: перед каждым правилом, которое ведёт в `select` или на сервер,
// встаёт то же правило «и запись из группы n» — на полосу n (или на копию сервера в полосе n).
// То же для «всё остальное» (final): правило группы в самом конце. Правила «мимо VPN»,
// блокировки, DNS не трогаются: куда идёт трафик, решают те же правила, что и раньше.
//
// Полос всегда LaneCount; группы меняются на лету: файлы перечитываются без переподключения,
// пустая полоса соединений не открывает (выход подключается при первом запросе). Полоса —
// селектор из копий серверов `select`, копия — «<сервер> §laneN§ §hide§». Endpoint'ы
// (WireGuard, AmneziaWG) не копируются: второй экземпляр с тем же ключом сломал бы первый,
// такой сервер полоса берёт сам. Сервер в полосах держит rescuestats.LaneSync — тот же, что в
// `select`.

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// LaneCount — сколько полос у ядра. Групп больше — остальные идут общим соединением.
const LaneCount = 8

// LaneMarker есть в теге каждой копии сервера: проверка пинга ядра такие выходы пропускает
// (заплатка 0004), иначе она держала бы открытыми соединения всех копий.
const LaneMarker = "§lane"

const laneGroupPrefix = "rescue-group-"

// LaneTag — тег селектора полосы n.
func LaneTag(n int) string { return fmt.Sprintf("rescue-lane-%d §hide§", n) }

// LaneCopyTag — тег копии сервера tag в полосе n.
func LaneCopyTag(tag string, n int) string {
	return fmt.Sprintf("%s %s%d§ §hide§", tag, LaneMarker, n)
}

// LaneGroupFile — файл записей группы, которой досталась полоса n.
func LaneGroupFile(n int) string { return fmt.Sprintf("group-%d.json", n) }

func laneGroupSet(n int) string { return fmt.Sprintf("%s%d", laneGroupPrefix, n) }

// IsLaneTag — выход служебный для полос (селектор или копия).
func IsLaneTag(tag string) bool {
	return strings.Contains(tag, LaneMarker) || strings.HasPrefix(tag, "rescue-lane-")
}

// lanes — что нужно applyLanes: число полос и серверы, у которых есть копии.
type lanes struct {
	count  int
	copied map[string]bool
}

// addLanes добавляет копии серверов и селекторы полос. Нет серверов — полос нет.
func addLanes(options *option.Options) lanes {
	servers := selectServers(options)
	if len(servers) == 0 {
		return lanes{}
	}
	byTag := make(map[string]option.Outbound, len(options.Outbounds))
	for _, out := range options.Outbounds {
		byTag[out.Tag] = out
	}
	res := lanes{count: LaneCount, copied: map[string]bool{}}
	var copies, selectors []option.Outbound
	for n := 0; n < LaneCount; n++ {
		members := make([]string, 0, len(servers))
		for _, tag := range servers {
			out, isOutbound := byTag[tag]
			if !isOutbound {
				members = append(members, tag) // endpoint: сам, без копии
				continue
			}
			cp := out
			cp.Tag = LaneCopyTag(tag, n)
			copies = append(copies, cp)
			members = append(members, cp.Tag)
			res.copied[tag] = true
		}
		selectors = append(selectors, option.Outbound{
			Type: C.TypeSelector,
			Tag:  LaneTag(n),
			Options: &option.SelectorOutboundOptions{
				Outbounds:                 members,
				Default:                   members[0],
				InterruptExistConnections: true,
			},
		})
	}
	options.Outbounds = append(options.Outbounds, selectors...)
	options.Outbounds = append(options.Outbounds, copies...)
	return res
}

// laneTarget — куда вести запись группы n вместо outbound; "" — правило не про VPN.
func (l lanes) laneTarget(outbound string, n int) string {
	switch {
	case outbound == OutboundSelectTag:
		return LaneTag(n)
	case l.copied[outbound]:
		return LaneCopyTag(outbound, n)
	}
	return ""
}

// matcher — условие правила без действия, для вложения в «и».
func matcher(r option.Rule) option.Rule {
	if r.Type == C.RuleTypeLogical {
		return option.Rule{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalRule{RawLogicalRule: r.LogicalOptions.RawLogicalRule}}
	}
	return option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: r.DefaultOptions.RawDefaultRule}}
}

func routeOf(r option.Rule) (option.RuleAction, bool) {
	a := r.DefaultOptions.RuleAction
	if r.Type == C.RuleTypeLogical {
		a = r.LogicalOptions.RuleAction
	}
	return a, a.Action == C.RuleActionTypeRoute || a.Action == ""
}

func withAction(r option.Rule, a option.RuleAction) option.Rule {
	if r.Type == C.RuleTypeLogical {
		r.LogicalOptions.RuleAction = a
	} else {
		r.DefaultOptions.RuleAction = a
	}
	return r
}

// applyLanes — см. описание файла. final — куда ведёт route.final.
func (l lanes) applyLanes(rules []option.Rule, final string) []option.Rule {
	if l.count == 0 {
		return rules
	}
	group := func(n int) option.Rule {
		return option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{RuleSet: []string{laneGroupSet(n)}},
		}}
	}
	out := make([]option.Rule, 0, len(rules)*2)
	for _, r := range rules {
		if action, isRoute := routeOf(r); isRoute {
			for n := 0; n < l.count; n++ {
				target := l.laneTarget(action.RouteOptions.Outbound, n)
				if target == "" {
					break
				}
				a := action
				a.Action = C.RuleActionTypeRoute
				a.RouteOptions.Outbound = target
				out = append(out, option.Rule{
					Type: C.RuleTypeLogical,
					LogicalOptions: option.LogicalRule{
						RawLogicalRule: option.RawLogicalRule{Mode: C.LogicalTypeAnd, Rules: []option.Rule{matcher(r), group(n)}},
						RuleAction:     a,
					},
				})
			}
		}
		out = append(out, r)
	}
	for n := 0; n < l.count; n++ {
		if target := l.laneTarget(final, n); target != "" {
			out = append(out, withAction(group(n), routeAction(target)))
		}
	}
	return out
}

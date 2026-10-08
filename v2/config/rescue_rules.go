package config

// Правила маршрутов «Шлюпки спасения» поверх правил Hiddify:
//   - пользовательские правила из приложения (hopt.Rules): домены, IP, порты, программы
//     (process_name/process_path — раздельное туннелирование по программам на Windows),
//     наборы правил; действие: через VPN, напрямую, напрямую с фрагментацией, блокировать;
//   - правила с сервера: секция route (и DNS) из подписки в формате sing-box.
//
// Hiddify строит маршруты сам и раньше отбрасывал и то и другое.
// Порядок: правила пользователя важнее правил сервера, оба важнее региона Hiddify.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	serverRuleSetPrefix = "server-"
	userRuleSetPrefix   = "user-"
	hiddifyGeoURL       = "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/"
)

type rescueRules struct {
	route       []option.Rule
	dns         []option.DefaultDNSRule
	ruleSets    []option.RuleSet
	findProcess bool
}

func (r *rescueRules) add(o rescueRules) {
	r.route = append(r.route, o.route...)
	r.dns = append(r.dns, o.dns...)
	r.ruleSets = append(r.ruleSets, o.ruleSets...)
	r.findProcess = r.findProcess || o.findProcess
}

func buildRescueRules(input *option.Options, hopt *HiddifyOptions) rescueRules {
	var res rescueRules
	res.add(userRules(hopt))
	if !hopt.IgnoreServerRules {
		res.add(serverRules(input, hopt))
	}
	return res
}

func remoteRuleSet(tag, url string, interval time.Duration) option.RuleSet {
	return option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    tag,
		Format: C.RuleSetFormatBinary,
		RemoteOptions: option.RemoteRuleSet{
			URL:            url,
			UpdateInterval: badoption.Duration(interval),
			// Через VPN: raw.githubusercontent.com в России бывает недоступен напрямую.
			DownloadDetour: OutboundSelectTag,
		},
	}
}

func directDNSRule(hopt *HiddifyOptions, raw option.RawDefaultDNSRule) option.DefaultDNSRule {
	return option.DefaultDNSRule{
		RawDefaultDNSRule: raw,
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:     DNSMultiDirectTag,
				Strategy:   hopt.DirectDnsDomainStrategy,
				RewriteTTL: &DEFAULT_DNS_TTL,
			},
		},
	}
}

func routeAction(outbound string) option.RuleAction {
	return option.RuleAction{
		Action:       C.RuleActionTypeRoute,
		RouteOptions: option.RouteActionOptions{Outbound: outbound},
	}
}

func rejectAction() option.RuleAction {
	return option.RuleAction{
		Action:        C.RuleActionTypeReject,
		RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
	}
}

// ---------- правила пользователя ----------

func userRules(hopt *HiddifyOptions) rescueRules {
	var res rescueRules
	rules := make([]*Rule, 0, len(hopt.Rules))
	for i := range hopt.Rules {
		if hopt.Rules[i].GetEnabled() {
			rules = append(rules, &hopt.Rules[i])
		}
	}
	sort.SliceStable(rules, func(a, b int) bool { return rules[a].GetListOrder() < rules[b].GetListOrder() })

	known := map[string]bool{}
	for _, r := range rules {
		raw := option.RawDefaultRule{
			Domain:        r.GetDomains(),
			DomainSuffix:  r.GetDomainSuffixes(),
			DomainKeyword: r.GetDomainKeywords(),
			DomainRegex:   r.GetDomainRegexes(),
			IPCIDR:        r.GetIpCidrs(),
			SourceIPCIDR:  r.GetSourceIpCidrs(),
			ProcessName:   r.GetProcessNames(),
			ProcessPath:   r.GetProcessPaths(),
			PackageName:   r.GetPackageNames(),
		}
		raw.Port, raw.PortRange = splitPorts(r.GetPortRanges())
		raw.SourcePort, raw.SourcePortRange = splitPorts(r.GetSourcePortRanges())
		switch r.GetNetwork() {
		case Network_tcp:
			raw.Network = []string{"tcp"}
		case Network_udp:
			raw.Network = []string{"udp"}
		}
		for _, p := range r.GetProtocols() {
			raw.Protocol = append(raw.Protocol, p.String())
		}
		for _, src := range r.GetRuleSets() {
			tag, url := userRuleSetSource(src)
			if tag == "" {
				continue
			}
			raw.RuleSet = append(raw.RuleSet, tag)
			if !known[tag] {
				known[tag] = true
				res.ruleSets = append(res.ruleSets, remoteRuleSet(tag, url, 24*time.Hour))
			}
		}
		if !hasMatcher(raw) {
			// Правило без условий совпало бы со всем трафиком.
			continue
		}
		if len(raw.ProcessName) > 0 || len(raw.ProcessPath) > 0 {
			res.findProcess = true
		}

		var action option.RuleAction
		direct := false
		switch r.GetOutbound() {
		case Outbound_direct:
			action, direct = routeAction(OutboundDirectTag), true
		case Outbound_direct_with_fragment:
			action, direct = routeAction(OutboundDirectFragmentTag), true
		case Outbound_block:
			action = rejectAction()
		default:
			action = routeAction(OutboundMainDetour)
		}
		res.route = append(res.route, option.Rule{
			Type:           C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{RawDefaultRule: raw, RuleAction: action},
		})

		// Сайты и программы мимо VPN резолвятся тоже мимо VPN: правильные адреса CDN
		// и никаких запросов к DNS через сервер для того, что идёт напрямую.
		if direct {
			dnsRaw := option.RawDefaultDNSRule{
				Domain:        raw.Domain,
				DomainSuffix:  raw.DomainSuffix,
				DomainKeyword: raw.DomainKeyword,
				DomainRegex:   raw.DomainRegex,
				ProcessName:   raw.ProcessName,
				ProcessPath:   raw.ProcessPath,
				PackageName:   raw.PackageName,
				RuleSet:       raw.RuleSet,
			}
			if hasDNSMatcher(dnsRaw) {
				res.dns = append(res.dns, directDNSRule(hopt, dnsRaw))
			}
		}
	}
	return res
}

// userRuleSetSource: «https://…/x.srs» или краткая запись «geoip:ru» / «geosite:ru»
// (страновые списки hiddify-geo). Остальное пропускается.
func userRuleSetSource(src string) (tag, url string) {
	src = strings.TrimSpace(src)
	lower := strings.ToLower(src)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"):
		sum := sha256.Sum256([]byte(src))
		return userRuleSetPrefix + hex.EncodeToString(sum[:6]), src
	case strings.HasPrefix(lower, "geoip:"), strings.HasPrefix(lower, "geosite:"):
		kind, code, _ := strings.Cut(lower, ":")
		if code == "" || strings.ContainsAny(code, "/.?#") {
			return "", ""
		}
		name := kind + "-" + code
		return userRuleSetPrefix + name, hiddifyGeoURL + name + ".srs"
	}
	return "", ""
}

// splitPorts: «443» → port, «1000:2000» и «1000-2000» (так подсказывает приложение) → port_range.
func splitPorts(items []string) (ports badoption.Listable[uint16], ranges badoption.Listable[string]) {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if from, to, ok := strings.Cut(strings.ReplaceAll(item, "-", ":"), ":"); ok {
			if _, err := strconv.ParseUint(from, 10, 16); err != nil {
				continue
			}
			if _, err := strconv.ParseUint(to, 10, 16); err != nil {
				continue
			}
			ranges = append(ranges, from+":"+to)
		} else if p, err := strconv.ParseUint(item, 10, 16); err == nil {
			ports = append(ports, uint16(p))
		}
	}
	return
}

func hasMatcher(r option.RawDefaultRule) bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.DomainRegex)+
		len(r.IPCIDR)+len(r.SourceIPCIDR)+len(r.Port)+len(r.PortRange)+
		len(r.SourcePort)+len(r.SourcePortRange)+len(r.ProcessName)+len(r.ProcessPath)+
		len(r.PackageName)+len(r.Protocol)+len(r.RuleSet) > 0 || r.IPIsPrivate
}

func hasDNSMatcher(r option.RawDefaultDNSRule) bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.DomainRegex)+
		len(r.ProcessName)+len(r.ProcessPath)+len(r.PackageName)+len(r.RuleSet) > 0
}

// ---------- правила сервера ----------

// serverRules переносит правила из подписки (sing-box JSON):
//   - выход «direct» → напрямую, «block» → блокировать, любой другой (selector, urltest,
//     сервер) → через VPN, как выберет пользователь в приложении;
//   - sniff, hijack-dns и правила с inbound пропускаются: их Hiddify ставит сам;
//   - наборы правил remote и inline копируются с префиксом server-;
//   - DNS: правило к серверу, который не final, считается «резолвить напрямую».
func serverRules(input *option.Options, hopt *HiddifyOptions) rescueRules {
	var res rescueRules
	if input == nil || input.Route == nil {
		return res
	}

	outboundType := map[string]string{}
	for _, o := range input.Outbounds {
		outboundType[o.Tag] = o.Type
	}

	sets := map[string]string{} // тег на сервере → наш тег
	for _, rs := range input.Route.RuleSet {
		tag := serverRuleSetPrefix + rs.Tag
		switch rs.Type {
		case C.RuleSetTypeRemote:
			interval := time.Duration(rs.RemoteOptions.UpdateInterval)
			if interval <= 0 {
				interval = 24 * time.Hour
			}
			set := remoteRuleSet(tag, rs.RemoteOptions.URL, interval)
			if rs.Format != "" {
				set.Format = rs.Format
			}
			res.ruleSets = append(res.ruleSets, set)
		case C.RuleSetTypeInline, "":
			set := rs
			set.Tag = tag
			res.ruleSets = append(res.ruleSets, set)
		default:
			continue // local: путь к файлу на чужой машине
		}
		sets[rs.Tag] = tag
	}

	renameSets := func(tags []string) ([]string, bool) {
		out := make([]string, 0, len(tags))
		for _, t := range tags {
			n, ok := sets[t]
			if !ok {
				return nil, false
			}
			out = append(out, n)
		}
		return out, true
	}

	for _, rule := range input.Route.Rules {
		if rule.Type != C.RuleTypeDefault && rule.Type != "" {
			continue // logical: редкость, пропускаем
		}
		r := rule.DefaultOptions
		if len(r.Inbound) > 0 || r.ClashMode != "" {
			continue
		}
		var action option.RuleAction
		switch r.Action {
		case C.RuleActionTypeRoute, "":
			switch outboundType[r.RouteOptions.Outbound] {
			case C.TypeDirect:
				action = routeAction(OutboundDirectTag)
			case C.TypeBlock:
				action = rejectAction()
			case "":
				continue // выход, которого нет в подписке
			default:
				action = routeAction(OutboundMainDetour)
			}
		case C.RuleActionTypeReject:
			action = rejectAction()
		default:
			continue // sniff, hijack-dns, resolve и прочее Hiddify делает сам
		}
		raw := r.RawDefaultRule
		if len(raw.RuleSet) > 0 {
			renamed, ok := renameSets(raw.RuleSet)
			if !ok {
				continue
			}
			raw.RuleSet = renamed
		}
		if !hasMatcher(raw) {
			continue
		}
		if len(raw.ProcessName) > 0 || len(raw.ProcessPath) > 0 || len(raw.ProcessPathRegex) > 0 {
			res.findProcess = true
		}
		res.route = append(res.route, option.Rule{
			Type:           C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{RawDefaultRule: raw, RuleAction: action},
		})
	}

	if input.DNS != nil {
		for _, rule := range input.DNS.Rules {
			if rule.Type != C.RuleTypeDefault && rule.Type != "" {
				continue
			}
			r := rule.DefaultOptions
			if r.Action != C.RuleActionTypeRoute && r.Action != "" {
				continue
			}
			if r.RouteOptions.Server == "" || r.RouteOptions.Server == input.DNS.Final {
				continue
			}
			raw := option.RawDefaultDNSRule{
				Domain:        r.Domain,
				DomainSuffix:  r.DomainSuffix,
				DomainKeyword: r.DomainKeyword,
				DomainRegex:   r.DomainRegex,
			}
			if len(r.RuleSet) > 0 {
				renamed, ok := renameSets(r.RuleSet)
				if !ok {
					continue
				}
				raw.RuleSet = renamed
			}
			if hasDNSMatcher(raw) {
				res.dns = append(res.dns, directDNSRule(hopt, raw))
			}
		}
	}
	return res
}

package config

// Раздельный туннель «Шлюпки спасения»: два списка, которые пользователь правит в приложении
// на лету, без переподключения.
//
// Приложение пишет в SplitTunnelDir файлы наборов правил sing-box (формат source):
//   via-vpn.json         программы, сайты, IP — всегда через VPN;
//   bypass-vpn.json      то же — всегда мимо VPN;
//   bypass-domains.json  только сайты из bypass-vpn.json: их DNS тоже идёт мимо VPN;
//   via-domains.json     только сайты из via-vpn.json: их DNS идёт через VPN и не режется
//                        блокировкой рекламы (файл необязательный, без него — пустой);
//   via-server-<key>.json  то, что пользователь закрепил за одним сервером из `select`
//                        (docs/rescue-servers-v2.md, key — ServerKey(тег)); файлы есть только
//                        для серверов профиля и только когда серверов два и больше.
// Это локальные наборы правил: sing-box следит за файлами и перечитывает их при изменении,
// а поиск программ включает сам, как только в наборе появляется правило по программе.
// Списки стоят выше всех остальных правил (сервера, региона, пользовательских); закреплённое
// за сервером — выше «через VPN».

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// ServerKey — ключ сервера для имён файлов (docs/rescue-servers-v2.md): первые 12 символов
// hex(sha256(UTF-8 тега)), строчные. Приложение считает так же.
func ServerKey(tag string) string {
	sum := sha256.Sum256([]byte(tag))
	return hex.EncodeToString(sum[:6])
}

const (
	splitViaTag           = "rescue-via-vpn"
	splitViaDomainsTag    = "rescue-via-domains"
	splitBypassTag        = "rescue-bypass-vpn"
	splitBypassDomainsTag = "rescue-bypass-domains"
	splitViaServerPrefix  = "rescue-via-server-"
)

// Пустой набор правил: файл должен существовать, иначе sing-box не запустится.
const emptyRuleSet = `{"version": 3, "rules": []}` + "\n"

// sing-box (filemanager.BasePath) считает абсолютным только путь, начинающийся с «/», а всё
// остальное приклеивает к рабочей папке ядра — в том числе «C:\...» на Windows, и файл не
// находится. Ядро при Setup делает Chdir в рабочую папку, поэтому отдаём путь относительно неё.
func ruleSetPath(p string) string {
	if strings.HasPrefix(p, "/") || !filepath.IsAbs(p) {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if rel, err := filepath.Rel(wd, p); err == nil {
		return rel
	}
	return p
}

// selectServers — серверы из выхода `select` по порядку, без групп (lowest, balance, другие
// селекторы). Тот же список, что у сторожа (rescuestats.failoverServers), но по options при
// сборке конфига: выходы и endpoint'ы (WireGuard и т. п.) — серверы, группы — нет.
func selectServers(options *option.Options) []string {
	if options == nil {
		return nil
	}
	known := make(map[string]bool) // тег → это сервер (не группа)
	var members []string
	for _, out := range options.Outbounds {
		switch out.Type {
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer:
			known[out.Tag] = false
			if sel, ok := out.Options.(*option.SelectorOutboundOptions); ok && out.Tag == OutboundSelectTag {
				members = sel.Outbounds
			}
		default:
			known[out.Tag] = true
		}
	}
	for _, end := range options.Endpoints {
		known[end.Tag] = true
	}
	var servers []string
	for _, tag := range members {
		if known[tag] {
			servers = append(servers, tag)
		}
	}
	return servers
}

func splitTunnelRules(options *option.Options, hopt *HiddifyOptions) rescueRules {
	var res rescueRules
	if hopt.SplitTunnelDir == "" {
		return res
	}
	path := func(name string) string {
		p := filepath.Join(hopt.SplitTunnelDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			_ = os.MkdirAll(hopt.SplitTunnelDir, 0o755)
			_ = os.WriteFile(p, []byte(emptyRuleSet), 0o644)
		}
		return ruleSetPath(p)
	}
	local := func(tag, name string) option.RuleSet {
		return option.RuleSet{
			Type:         C.RuleSetTypeLocal,
			Tag:          tag,
			Format:       C.RuleSetFormatSource,
			LocalOptions: option.LocalRuleSet{Path: path(name)},
		}
	}
	res.ruleSets = []option.RuleSet{
		local(splitViaTag, "via-vpn.json"),
		local(splitViaDomainsTag, "via-domains.json"),
		local(splitBypassTag, "bypass-vpn.json"),
		local(splitBypassDomainsTag, "bypass-domains.json"),
	}
	// Пункты, закреплённые за сервером: свой набор на каждый сервер и правило прямо на его
	// выход, выше «через VPN». При одном сервере закреплять не за что — как раньше.
	if servers := selectServers(options); len(servers) >= 2 {
		for _, tag := range servers {
			key := ServerKey(tag)
			setTag := splitViaServerPrefix + key
			res.ruleSets = append(res.ruleSets, local(setTag, "via-server-"+key+".json"))
			res.route = append(res.route, option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{RuleSet: []string{setTag}},
					RuleAction:     routeAction(tag),
				},
			})
		}
	}
	res.route = append(res.route, []option.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{RuleSet: []string{splitViaTag}},
				RuleAction:     routeAction(OutboundMainDetour),
			},
		},
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{RuleSet: []string{splitBypassTag}},
				RuleAction:     routeAction(OutboundDirectTag),
			},
		},
	}...)
	// Вкладка «Сейчас в сети» показывает, какая программа куда идёт: имя процесса нужно для
	// каждого соединения, а не только когда в списках есть программы.
	res.findProcess = isWindows
	// DNS-правила списков стоят выше блокировки рекламы: сайт, который пользователь сам
	// добавил в список, не должен получить отказ от geosite-ads. «Через VPN» первым, как и
	// в маршрутах: если сайт в обоих списках, побеждает «через VPN».
	res.dns = []option.DefaultDNSRule{
		remoteDNSRule(hopt, option.RawDefaultDNSRule{RuleSet: []string{splitViaDomainsTag}}),
		directDNSRule(hopt, option.RawDefaultDNSRule{RuleSet: []string{splitBypassDomainsTag}}),
	}
	return res
}

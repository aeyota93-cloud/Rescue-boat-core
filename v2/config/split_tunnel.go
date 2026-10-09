package config

// Раздельный туннель «Шлюпки спасения»: два списка, которые пользователь правит в приложении
// на лету, без переподключения.
//
// Приложение пишет в SplitTunnelDir файлы наборов правил sing-box (формат source):
//   via-vpn.json         программы, сайты, IP — всегда через VPN;
//   bypass-vpn.json      то же — всегда мимо VPN;
//   bypass-domains.json  только сайты из bypass-vpn.json: их DNS тоже идёт мимо VPN.
// Это локальные наборы правил: sing-box следит за файлами и перечитывает их при изменении,
// а поиск программ включает сам, как только в наборе появляется правило по программе.
// Оба списка стоят выше всех остальных правил (сервера, региона, пользовательских).

import (
	"os"
	"path/filepath"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	splitViaTag           = "rescue-via-vpn"
	splitBypassTag        = "rescue-bypass-vpn"
	splitBypassDomainsTag = "rescue-bypass-domains"
)

// Пустой набор правил: файл должен существовать, иначе sing-box не запустится.
const emptyRuleSet = `{"version": 3, "rules": []}` + "\n"

func splitTunnelRules(hopt *HiddifyOptions) rescueRules {
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
		return p
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
		local(splitBypassTag, "bypass-vpn.json"),
		local(splitBypassDomainsTag, "bypass-domains.json"),
	}
	res.route = []option.Rule{
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
	}
	res.dns = []option.DefaultDNSRule{
		directDNSRule(hopt, option.RawDefaultDNSRule{RuleSet: []string{splitBypassDomainsTag}}),
	}
	return res
}

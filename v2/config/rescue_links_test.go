package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Как PasarGuard отдаёт `<подписка>/links`: основной (уже есть в JSON) и запасной XHTTP.
const testRescueLinks = "vless://00000000-0000-4000-8000-000000000000@203.0.113.10:443?encryption=none&security=reality&type=raw&flow=xtls-rprx-vision&sni=vpn.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#NL\n" +
	"vless://00000000-0000-4000-8000-000000000000@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fsecret&mode=auto&sni=backup.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#NL%20%D0%B7%D0%B0%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D0%B9\n"

func subscriptionWithLinks(t *testing.T, links string) string {
	t.Helper()
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(testSubscription), &obj); err != nil {
		t.Fatal(err)
	}
	obj[rescueLinksKey] = links
	b, _ := json.Marshal(obj)
	return string(b)
}

func vlessTags(o *option.Options) []string {
	var tags []string
	for _, out := range o.Outbounds {
		if out.Type == C.TypeVLESS {
			tags = append(tags, out.Tag)
		}
	}
	return tags
}

func TestRescueLinksAddMissingServers(t *testing.T) {
	o := buildTestConfig(t, subscriptionWithLinks(t, testRescueLinks), DefaultHiddifyOptions())

	if got := vlessTags(o); !slices.Equal(got, []string{"NL", "NL запасной"}) {
		t.Fatalf("серверы: %v, нужен основной из JSON и запасной из ссылок, без дублей", got)
	}
	for _, out := range o.Outbounds {
		if out.Tag == OutboundSelectTag {
			sel := out.Options.(*option.SelectorOutboundOptions)
			i, j := slices.Index(sel.Outbounds, "NL"), slices.Index(sel.Outbounds, "NL запасной")
			if i < 0 || j < 0 || i > j {
				t.Errorf("в выборе основной должен идти раньше запасного: %v", sel.Outbounds)
			}
		}
		if out.Tag == "NL запасной" {
			b, _ := json.Marshal(out.Options)
			if !strings.Contains(string(b), `"xhttp"`) {
				t.Errorf("запасной без транспорта XHTTP: %s", b)
			}
		}
	}
	if !slices.Contains(ruleSetTags(o), "server-ru-ip") {
		t.Error("правила сервера из JSON потерялись")
	}
}

func TestRescueLinksBrokenIgnored(t *testing.T) {
	o := buildTestConfig(t, subscriptionWithLinks(t, "не ссылка вовсе"), DefaultHiddifyOptions())
	if got := vlessTags(o); !slices.Equal(got, []string{"NL"}) {
		t.Fatalf("при битых ссылках остаются серверы JSON: %v", got)
	}
}

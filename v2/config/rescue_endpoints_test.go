package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// Ключи вымышленные, адреса из тестовых диапазонов.
const testRescueEndpoints = `[
  {"type":"awg","tag":"РФ-NL AWG","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
   "address":["10.66.66.2/32"],"mtu":1200,"jc":4,"jmin":40,"jmax":70,
   "s1":0,"s2":0,"s3":0,"s4":0,"h1":"1-2","h2":"3-4","h3":"5-6","h4":"7-8",
   "peers":[{"address":"203.0.113.10","port":51821,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
             "allowed_ips":["0.0.0.0/0"],"persistent_keepalive_interval":25}]},
  {"type":"awg","tag":"NL AWG","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
   "address":["10.66.66.3/32"],"mtu":1200,
   "peers":[{"address":"198.51.100.10","port":51821,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
             "allowed_ips":["0.0.0.0/0"],"persistent_keepalive_interval":25}]}
]`

func rescueEndpointsFixture(t *testing.T) []interface{} {
	t.Helper()
	var endpoints []interface{}
	if err := json.Unmarshal([]byte(testRescueEndpoints), &endpoints); err != nil {
		t.Fatal(err)
	}
	return endpoints
}

func TestRescueEndpointsBuild(t *testing.T) {
	for _, asString := range []bool{false, true} {
		t.Run(map[bool]string{false: "массив", true: "тело ответа"}[asString], func(t *testing.T) {
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(testSubscription), &obj); err != nil {
				t.Fatal(err)
			}
			obj[rescueEndpointsKey] = rescueEndpointsFixture(t)
			if asString {
				obj[rescueEndpointsKey] = testRescueEndpoints
			}
			b, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			o := buildTestConfig(t, string(b), DefaultHiddifyOptions())
			var tags []string
			for _, endpoint := range o.Endpoints {
				tags = append(tags, endpoint.Tag)
			}
			want := []string{"РФ-NL AWG", "NL AWG"}
			if !slices.Equal(tags, want) {
				t.Fatalf("endpoints: %v, нужны %v", tags, want)
			}
			for _, group := range []string{OutboundSelectTag, OutboundRoundRobinTag} {
				var members []string
				for _, out := range o.Outbounds {
					if out.Tag != group {
						continue
					}
					switch opts := out.Options.(type) {
					case *option.SelectorOutboundOptions:
						members = opts.Outbounds
					case *option.BalancerOutboundOptions:
						members = opts.Outbounds
					}
				}
				i, j := slices.Index(members, want[0]), slices.Index(members, want[1])
				if i < 0 || j <= i {
					t.Errorf("в %s нет AWG в порядке ответа: %v", group, members)
				}
			}
		})
	}
}

func TestRescueEndpointsAppend(t *testing.T) {
	extra := rescueEndpointsFixture(t)
	old := map[string]interface{}{"type": "awg", "tag": "старый"}
	obj := map[string]interface{}{"endpoints": []interface{}{old}, rescueEndpointsKey: extra}
	mergeRescueEndpoints(obj)
	if _, ok := obj[rescueEndpointsKey]; ok {
		t.Fatal("служебное поле осталось в профиле")
	}
	if !reflect.DeepEqual(obj["endpoints"], append([]interface{}{old}, extra...)) {
		t.Fatal("endpoints должны добавляться в конец без изменений")
	}
}

func TestRescueEndpointsInvalidObject(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]interface{})
	}{
		{"не AWG", func(e map[string]interface{}) { e["type"] = "wireguard" }},
		{"нет тега", func(e map[string]interface{}) { delete(e, "tag") }},
		{"пустой тег", func(e map[string]interface{}) { e["tag"] = " " }},
		{"тег outbound", func(e map[string]interface{}) { e["tag"] = "выход" }},
		{"тег endpoint", func(e map[string]interface{}) { e["tag"] = "endpoint" }},
		{"нет ключа", func(e map[string]interface{}) { delete(e, "private_key") }},
		{"пустой ключ", func(e map[string]interface{}) { e["private_key"] = "" }},
		{"нет адреса", func(e map[string]interface{}) { delete(e, "address") }},
		{"плохой адрес", func(e map[string]interface{}) { e["address"] = []string{"мусор"} }},
		{"нет пиров", func(e map[string]interface{}) { delete(e, "peers") }},
		{"домен", func(e map[string]interface{}) {
			e["peers"].([]interface{})[0].(map[string]interface{})["address"] = "vpn.example.com"
		}},
		{"IPv6", func(e map[string]interface{}) {
			e["peers"].([]interface{})[0].(map[string]interface{})["address"] = "2001:db8::1"
		}},
		{"нет порта", func(e map[string]interface{}) { delete(e["peers"].([]interface{})[0].(map[string]interface{}), "port") }},
		{"порт вне диапазона", func(e map[string]interface{}) { e["peers"].([]interface{})[0].(map[string]interface{})["port"] = 65536 }},
		{"дробный порт", func(e map[string]interface{}) { e["peers"].([]interface{})[0].(map[string]interface{})["port"] = 1.5 }},
		{"неверный второй пир", func(e map[string]interface{}) {
			e["peers"] = append(e["peers"].([]interface{}), map[string]interface{}{"address": "vpn.example.com", "port": 51821})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := rescueEndpointsFixture(t)
			tc.change(extra[0].(map[string]interface{}))
			old := map[string]interface{}{"tag": "endpoint"}
			obj := map[string]interface{}{
				"outbounds": []interface{}{map[string]interface{}{"tag": "выход"}},
				"endpoints": []interface{}{old}, rescueEndpointsKey: extra,
			}
			mergeRescueEndpoints(obj)
			if !reflect.DeepEqual(obj["endpoints"], []interface{}{old, extra[1]}) {
				t.Fatal("неверный объект нужно пропустить, следующий — добавить")
			}
			if _, ok := obj[rescueEndpointsKey]; ok {
				t.Fatal("служебное поле осталось в профиле")
			}
		})
	}
}

func TestRescueEndpointsDuplicateInArray(t *testing.T) {
	extra := rescueEndpointsFixture(t)
	obj := map[string]interface{}{rescueEndpointsKey: []interface{}{extra[0], extra[0], extra[1]}}
	mergeRescueEndpoints(obj)
	if !reflect.DeepEqual(obj["endpoints"], extra) {
		t.Fatal("повтор тега внутри массива нужно пропустить")
	}
}

func TestRescueEndpointsGarbage(t *testing.T) {
	for _, raw := range []interface{}{nil, 42, true, map[string]interface{}{}, "мусор", "[", "null", "{}", `[{"private_key":"секрет"},`, []interface{}{nil, "мусор", 42}} {
		obj := map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"tag": "старый"}}, rescueEndpointsKey: raw}
		before, _ := json.Marshal(obj["endpoints"])
		mergeRescueEndpoints(obj)
		after, _ := json.Marshal(obj["endpoints"])
		if string(before) != string(after) {
			t.Fatal("мусор изменил endpoints")
		}
		if _, ok := obj[rescueEndpointsKey]; ok {
			t.Fatal("служебное поле осталось в профиле")
		}
	}
}

func TestRescueEndpointsAbsent(t *testing.T) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(testSubscription), &obj); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(obj)
	mergeRescueEndpoints(obj)
	after, _ := json.Marshal(obj)
	if string(before) != string(after) {
		t.Fatal("без rescue-endpoints профиль не должен меняться")
	}
}

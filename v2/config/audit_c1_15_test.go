package config

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

func auditC115Endpoint(t *testing.T, field string, secondPeer bool, value string) map[string]interface{} {
	t.Helper()
	e := rescueEndpointsFixture(t)[0].(map[string]interface{})
	if field == "private_key" {
		e[field] = value
		return e
	}
	peers := e["peers"].([]interface{})
	peer := peers[0].(map[string]interface{})
	if secondPeer {
		other := make(map[string]interface{}, len(peer))
		for k, v := range peer {
			other[k] = v
		}
		peers = append(peers, other)
		e["peers"] = peers
		peer = other
	}
	peer[field] = value
	return e
}

func TestAudit_C1_15_BadAWGKeyDoesNotRejectSubscription(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		second      bool
	}{
		{"private", "private_key", false},
		{"public-first", "public_key", false},
		{"public-second", "public_key", true},
		{"preshared", "preshared_key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(testSubscription), &obj); err != nil {
				t.Fatalf("C1-15: ожидался тестовый JSON, получено %v", err)
			}
			// Единственный AWG заведомо битый: genIpcConfig вернёт ошибку до NewDevice.
			obj[rescueEndpointsKey] = []interface{}{auditC115Endpoint(t, tc.field, tc.second, "%%%")}
			body, err := json.Marshal(obj)
			if err != nil {
				t.Fatalf("C1-15: ожидалась сериализация подписки, получено %v", err)
			}
			parsed, err := ParseConfig(libbox.BaseContext(nil), &ReadOptions{Content: string(body)}, false, nil, false)
			if err != nil {
				t.Fatalf("C1-15: ожидался импорт VLESS с пропуском битого AWG, получено %v", err)
			}
			found := false
			for _, out := range parsed.Outbounds {
				if out.Tag == "NL" && out.Type == "vless" {
					found = true
				}
			}
			if !found || len(parsed.Endpoints) != 0 {
				t.Errorf("C1-15: ожидались сохранённый VLESS и отсутствие битого AWG, VLESS=%t, endpoints=%d", found, len(parsed.Endpoints))
			}
		})
	}
}

func TestAudit_C1_15_AWGKeysMustDecodeTo32Bytes(t *testing.T) {
	for _, field := range []string{"private_key", "public_key", "preshared_key"} {
		for _, size := range []int{31, 33} {
			e := auditC115Endpoint(t, field, false, base64.StdEncoding.EncodeToString(make([]byte, size)))
			if validRescueEndpoint(e) {
				t.Errorf("C1-15: ожидался отказ для %s длиной %d байт, endpoint принят", field, size)
			}
		}
	}
}

package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
)

const rescueEndpointsKey = "rescue-endpoints"

// Готовые AWG endpoints дописываются в порядке ответа сервера.
func mergeRescueEndpoints(obj map[string]interface{}) {
	raw, ok := obj[rescueEndpointsKey]
	delete(obj, rescueEndpointsKey)
	if !ok {
		return
	}
	if body, ok := raw.(string); ok {
		if err := json.Unmarshal([]byte(body), &raw); err != nil {
			fmt.Println("[rescue-endpoints] поле пропущено: неверный JSON")
			return
		}
	}
	extra, ok := raw.([]interface{})
	if !ok {
		fmt.Println("[rescue-endpoints] поле пропущено: нужен массив")
		return
	}
	known := map[string]bool{}
	for _, list := range []string{"outbounds", "endpoints"} {
		items, _ := obj[list].([]interface{})
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				if tag, ok := m["tag"].(string); ok {
					known[tag] = true
				}
			}
		}
	}
	endpoints, _ := obj["endpoints"].([]interface{})
	for i, item := range extra {
		endpoint, ok := item.(map[string]interface{})
		tag, _ := endpoint["tag"].(string)
		if !ok || endpoint["type"] != "awg" || strings.TrimSpace(tag) == "" || !validRescueEndpoint(endpoint) {
			fmt.Printf("[rescue-endpoints] объект %d пропущен: неверный AWG endpoint\n", i+1)
			continue
		}
		if known[tag] {
			fmt.Printf("[rescue-endpoints] объект %d пропущен: тег уже есть\n", i+1)
			continue
		}
		known[tag] = true
		endpoints = append(endpoints, endpoint)
		obj["endpoints"] = endpoints
	}
}

func validRescueEndpoint(endpoint map[string]interface{}) bool {
	b, err := json.Marshal(endpoint)
	if err != nil {
		return false
	}
	var opts option.AwgEndpointOptions
	if err := json.Unmarshal(b, &opts); err != nil {
		return false
	}
	if strings.TrimSpace(opts.PrivateKey) == "" || len(opts.Address) == 0 || len(opts.Peers) == 0 {
		return false
	}
	for _, peer := range opts.Peers {
		ip, err := netip.ParseAddr(peer.Address)
		if err != nil || !ip.Is4() || peer.Port == 0 {
			return false
		}
	}
	return true
}

package config

// Шлюпка: серверы, которых нет в подписке sing-box, но есть в той же подписке в формате ссылок.
//
// PasarGuard не кладёт в подписку sing-box входы с транспортом XHTTP (обычный sing-box его не
// знает), а ядро Шлюпки знает (ray2sing). Приложение скачивает `<подписка>/links` и кладёт текст
// в поле `rescue-links` JSON-подписки; здесь ссылки превращаются в выходы и дописываются в конец
// списка выходов — только те, чьего тега в подписке ещё нет. Порядок важен: сторож
// автопереключения (rescuestats/failover.go) считает основным первый сервер.
// Ссылки, которые не разобрались, молча пропускаются: подписка sing-box главнее.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/hiddify/ray2sing/ray2sing"
)

const rescueLinksKey = "rescue-links"

// ray2sing дописывает к имени из ссылки « § <номер>»; в подписке sing-box имена без него.
var ray2singTagSuffix = regexp.MustCompile(` § \d+$`)

func mergeRescueLinks(ctx context.Context, obj map[string]interface{}, configOpt *HiddifyOptions) {
	raw, ok := obj[rescueLinksKey]
	delete(obj, rescueLinksKey)
	links, _ := raw.(string)
	if !ok || links == "" {
		return
	}
	outbounds, _ := obj["outbounds"].([]interface{})
	if outbounds == nil {
		return
	}
	extra, err := rescueLinkOutbounds(ctx, links, configOpt)
	if err != nil {
		fmt.Printf("[rescue-links] пропущены: %v\n", err)
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
	for _, out := range extra {
		tag, _ := out["tag"].(string)
		tag = ray2singTagSuffix.ReplaceAllString(tag, "")
		if tag == "" || known[tag] {
			continue
		}
		known[tag] = true
		out["tag"] = tag
		outbounds = append(outbounds, out)
	}
	obj["outbounds"] = outbounds
}

func rescueLinkOutbounds(ctx context.Context, links string, configOpt *HiddifyOptions) ([]map[string]interface{}, error) {
	useXray := configOpt != nil && configOpt.UseXrayCoreWhenPossible
	opts, err := ray2sing.Ray2SingboxOptions(ctx, links, useXray)
	if err != nil {
		return nil, err
	}
	b, err := opts.MarshalJSONContext(ctx)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return nil, err
	}
	return parsed.Outbounds, nil
}

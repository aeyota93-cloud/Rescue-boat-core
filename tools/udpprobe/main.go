package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/hiddify/hiddify-core/v2/rescuestats"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func main() {
	if err := run(); err != nil {
		// Исходные ошибки могут содержать секреты из конфига.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("укажите путь к JSON-конфигу")
	}
	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		return errors.New("не удалось прочитать конфиг")
	}
	content, err = cleanConfig(content)
	if err != nil {
		return errors.New("не удалось разобрать конфиг")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx = include.Context(ctx)
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, content)
	if err != nil {
		return errors.New("не удалось разобрать конфиг sing-box")
	}
	// Журнал отключён, чтобы адреса и учётные данные не попали в вывод.
	opts.Log = &option.LogOptions{Disabled: true}
	// Некоторые endpoints создают сетевые интерфейсы при запуске.
	if len(opts.Endpoints) != 0 || len(opts.Services) != 0 {
		return errors.New("для проверки нужен конфиг без endpoints и services")
	}
	for _, ob := range opts.Outbounds {
		if wg, ok := ob.Options.(*option.LegacyWireGuardOutboundOptions); ok && wg.SystemInterface {
			return errors.New("выход требует системный TUN")
		}
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return errors.New("не удалось создать sing-box")
	}
	defer instance.Close()
	if instance.Start() != nil {
		return errors.New("не удалось запустить sing-box")
	}
	type result struct {
		tag, udp, tcp string
	}
	var results []result
	var outbounds []adapter.Outbound
	for _, ob := range instance.Outbound().Outbounds() {
		if _, group := ob.(adapter.OutboundGroup); group {
			continue
		}
		switch ob.Type() {
		case "direct", "block", "dns":
			continue
		}
		outbounds = append(outbounds, ob)
		results = append(results, result{tag: ob.Tag()})
	}
	var wg sync.WaitGroup
	for i, ob := range outbounds {
		wg.Add(1)
		go func(i int, ob adapter.Outbound) {
			defer wg.Done()
			probeCtx, finish := context.WithTimeout(ctx, rescuestats.ProbeUDPTimeout)
			defer finish()
			var probes sync.WaitGroup
			probes.Add(2)
			go func() {
				defer probes.Done()
				results[i].udp = "UDP ok"
				if err := rescuestats.ProbeUDP(probeCtx, ob); err != nil {
					results[i].udp = "UDP ошибка (" + briefError(probeCtx) + ")"
				}
			}()
			go func() {
				defer probes.Done()
				// Тот же адрес по умолчанию, что в rescuestats/probe.go.
				ms, err := urltest.URLTest(probeCtx, "http://cp.cloudflare.com/", ob)
				results[i].tcp = fmt.Sprintf("TCP %d мс", ms)
				if err != nil {
					results[i].tcp = "TCP ошибка (" + briefError(probeCtx) + ")"
				}
			}()
			probes.Wait()
		}(i, ob)
	}
	wg.Wait()
	for _, r := range results {
		// Кавычки экранируют переносы строк и управляющие символы в теге.
		fmt.Printf("%q\t%s\t%s\n", r.tag, r.udp, r.tcp)
	}
	return nil
}

func briefError(ctx context.Context) string {
	switch ctx.Err() {
	case context.Canceled:
		return "отмена"
	case context.DeadlineExceeded:
		return "тайм-аут"
	default:
		return "нет ответа"
	}
}

func cleanConfig(content []byte) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	delete(root, "inbounds")
	delete(root, "experimental")
	for section, keys := range map[string][]string{"route": {"rules", "rule_set"}, "dns": {"rules"}} {
		if raw, ok := root[section]; ok && string(raw) != "null" {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return nil, err
			}
			for _, key := range keys {
				delete(fields, key)
			}
			encoded, err := json.Marshal(fields)
			if err != nil {
				return nil, err
			}
			root[section] = encoded
		}
	}
	return json.Marshal(root)
}

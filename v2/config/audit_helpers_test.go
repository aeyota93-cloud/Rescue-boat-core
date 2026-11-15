package config

import "github.com/sagernet/sing-box/option"

// Только сборка Options: адреса числовые, списки и запись логов выключены.
func auditC1Options() *HiddifyOptions {
	o := DefaultHiddifyOptions()
	o.ConnectionTestUrl = "http://192.0.2.1/generate_204"
	o.ConnectionTestUrls = []string{o.ConnectionTestUrl}
	o.EnableClashApi = false
	o.LogFile = ""
	o.Region = "other"
	o.BalancerStrategy = "round-robin"
	return o
}

func auditC1Servers() *option.Options {
	return &option.Options{Outbounds: []option.Outbound{
		{Type: "socks", Tag: "A", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.10", ServerPort: 1080}}},
		{Type: "socks", Tag: "B", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.11", ServerPort: 1080}}},
	}}
}

package config

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestAudit_C1_10_NoVisibleServersReturnsError(t *testing.T) {
	hidden := auditC1Servers()
	hidden.Outbounds = hidden.Outbounds[:1]
	hidden.Outbounds[0].Tag = "A §hide§"
	for _, tc := range []struct {
		name  string
		input *option.Options
	}{
		{"empty", &option.Options{}},
		{"direct", &option.Options{Outbounds: []option.Outbound{{Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}}}}},
		{"hidden-socks", hidden},
		{"selector", &option.Options{Outbounds: []option.Outbound{
			{Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}},
			{Type: "selector", Tag: "proxy", Options: &option.SelectorOutboundOptions{Outbounds: []string{"direct"}}},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("C1-10: ожидалась ошибка об отсутствии серверов без паники, получена паника: %v", p)
				}
			}()
			_, err := BuildConfig(context.Background(), auditC1Options(), &ReadOptions{Options: tc.input})
			if err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("C1-10: ожидалась содержательная ошибка об отсутствии серверов, получено %v", err)
			}
		})
	}
}

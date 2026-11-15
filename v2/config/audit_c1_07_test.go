package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// Гонка общих detour-переменных ловится только с -race.
// Проверка результатов дополнительно обнаруживает смешение WARP on/off.
func TestAudit_C1_07_ParallelBuildsKeepOwnDetours(t *testing.T) {
	oldMain, oldWarp := OutboundMainDetour, OutboundWARPConfigDetour
	defer func() { OutboundMainDetour, OutboundWARPConfigDetour = oldMain, oldWarp }()
	start := make(chan struct{})
	done := make(chan error, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, warp := range []bool{false, true} {
		go func(warp bool) {
			var result error
			defer func() {
				if p := recover(); p != nil {
					result = fmt.Errorf("C1-07: ожидалась сборка без паники, получено %v", p)
				}
				done <- result
			}()
			<-start
			want := OutboundSelectTag
			if warp {
				want = WARPConfigTag
			}
			for i := 0; i < 200; i++ {
				if ctx.Err() != nil {
					result = fmt.Errorf("C1-07: ожидалось 200 сборок за 2 с, получено %d", i)
					return
				}
				h := auditC1Options()
				h.Warp.EnableWarp = warp
				// У каждого вызова собственные настройки и входные Options.
				built, err := BuildConfig(ctx, h, &ReadOptions{Options: auditC1Servers()})
				if err != nil {
					result = fmt.Errorf("C1-07: ожидалась сборка WARP=%t, получено %v", warp, err)
					return
				}
				if built.Route == nil {
					result = fmt.Errorf("C1-07: ожидался Route для WARP=%t, получено nil", warp)
					return
				}
				if built.Route.Final != want && result == nil {
					result = fmt.Errorf("C1-07: для WARP=%t ожидался Route.Final=%q, получено %q", warp, want, built.Route.Final)
				}
				found := false
				for _, server := range built.DNS.Servers {
					if server.Tag != DNSRemoteTag {
						continue
					}
					found = true
					o, ok := server.Options.(*option.RemoteDNSServerOptions)
					if (!ok || o.Detour != want) && result == nil {
						result = fmt.Errorf("C1-07: для WARP=%t ожидался detour DNS=%q, получено %+v", warp, want, server.Options)
					}
				}
				if !found {
					result = fmt.Errorf("C1-07: ожидался удалённый DNS, сервер отсутствует")
					return
				}
			}
		}(warp)
	}
	close(start)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-deadline.C:
			t.Fatal("C1-07: ожидалось завершение параллельных сборок за 3 с, сборки не завершились")
		}
	}
}

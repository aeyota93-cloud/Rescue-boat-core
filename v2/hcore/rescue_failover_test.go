package hcore

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/sagernet/sing-box/adapter"
)

// rescue-failover выключен — сторожа нет; включён — есть и без rescue-stats-dir.
func TestNewRescueFailoverOnlyWithOption(t *testing.T) {
	saved := static.HiddifyOptions
	defer func() { static.HiddifyOptions = saved }()

	static.HiddifyOptions = nil
	if newRescueFailover() != nil {
		t.Error("failover without options")
	}
	static.HiddifyOptions = config.DefaultHiddifyOptions()
	if newRescueFailover() != nil {
		t.Error("failover with rescue-failover=false")
	}
	static.HiddifyOptions.RescueFailover = true
	f := newRescueFailover()
	if f == nil {
		t.Fatal("no failover with rescue-failover=true")
	}
	if f.Running() {
		t.Error("running before start")
	}
	_ = f.Close()
}

func TestRescueFailoverOption(t *testing.T) {
	var opt config.HiddifyOptions
	if err := json.Unmarshal([]byte(`{"rescue-failover":true}`), &opt); err != nil {
		t.Fatal(err)
	}
	if !opt.RescueFailover {
		t.Error("option not parsed")
	}
	data, err := json.Marshal(config.HiddifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	if _, ok := m["rescue-failover"]; ok {
		t.Error("false option must be omitted")
	}
}

// Повторные включения не зависят от каталога статистики и не запускают пробы
// до готовности ядра. Выключенная опция не создаёт даже службу.
func TestRescueFailoverToggleAndLifecycle(t *testing.T) {
	saved := static.HiddifyOptions
	t.Cleanup(func() { static.HiddifyOptions = saved })
	dir := t.TempDir()
	static.HiddifyOptions = config.DefaultHiddifyOptions()
	static.HiddifyOptions.RescueStatsDir = dir
	for _, enabled := range []bool{true, false, true, false} {
		static.HiddifyOptions.RescueFailover = enabled
		f := newRescueFailover()
		if !enabled {
			if f != nil {
				t.Fatal("watcher created while disabled")
			}
			continue
		}
		if f == nil || f.Name() != "rescue-failover" {
			t.Fatal("watcher missing")
		}
		for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart, adapter.StartStateStarted} {
			if err := f.Start(stage); err != nil {
				t.Fatal(err)
			}
		}
		if f.Running() {
			t.Fatal("watcher started without box")
		}
		for i := 0; i < 2; i++ {
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected stats before core start: %v, %v", entries, err)
	}
}

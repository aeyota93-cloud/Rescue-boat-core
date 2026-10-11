package hcore

import (
	"encoding/json"
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
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

package hcore

import (
	"encoding/json"
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
)

// Пустой rescue-compare-dir — службы нет; папка задана — служба есть и без rescue-stats-dir.
func TestNewRescueCompareOnlyWithDir(t *testing.T) {
	saved := static.HiddifyOptions
	defer func() { static.HiddifyOptions = saved }()

	static.HiddifyOptions = nil
	if newRescueCompare() != nil {
		t.Error("service without options")
	}
	static.HiddifyOptions = config.DefaultHiddifyOptions()
	if newRescueCompare() != nil {
		t.Error("service with empty rescue-compare-dir")
	}
	static.HiddifyOptions.RescueCompareDir = t.TempDir()
	if newRescueCompare() == nil {
		t.Error("no service with rescue-compare-dir")
	}
	if newRescueStats() != nil {
		t.Error("rescue-compare-dir must not enable the stats collector")
	}
}

func TestRescueCompareDirOption(t *testing.T) {
	var opt config.HiddifyOptions
	if err := json.Unmarshal([]byte(`{"rescue-compare-dir":"C:/data/compare"}`), &opt); err != nil {
		t.Fatal(err)
	}
	if opt.RescueCompareDir != "C:/data/compare" {
		t.Errorf("dir = %q", opt.RescueCompareDir)
	}
	data, err := json.Marshal(config.HiddifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	if _, ok := m["rescue-compare-dir"]; ok {
		t.Error("empty option must be omitted")
	}
}

package hcore

import (
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
)

// Пустой rescue-stats-dir — сборщика нет: ядро ничего не пишет и не замеряет.
func TestNewRescueStatsOnlyWithDir(t *testing.T) {
	saved := static.HiddifyOptions
	defer func() { static.HiddifyOptions = saved }()

	static.HiddifyOptions = nil
	if newRescueStats() != nil {
		t.Error("collector without options")
	}
	static.HiddifyOptions = config.DefaultHiddifyOptions()
	if newRescueStats() != nil {
		t.Error("collector with empty rescue-stats-dir")
	}
	static.HiddifyOptions.RescueStatsDir = t.TempDir()
	if newRescueStats() == nil {
		t.Error("no collector with rescue-stats-dir")
	}
}

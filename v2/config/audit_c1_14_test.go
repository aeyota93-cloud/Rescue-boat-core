package config

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/sing/service/filemanager"
)

func TestAudit_C1_14_CrossVolumeRuleSetThroughFileManager(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("C1-14: нужны правила путей Windows; на этой ОС сценарий другого тома неприменим")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("C1-14: ожидалась рабочая папка, получено %v", err)
	}
	drive := `D:`
	if strings.EqualFold(filepath.VolumeName(wd), drive) {
		drive = `E:`
	}
	ctx := filemanager.WithDefault(context.Background(), wd, t.TempDir(), os.Getuid(), os.Getgid())
	// Только строки: существование другого диска и доступ к UNC не нужны.
	for _, candidate := range []string{drive + `\Split\via-vpn.json`, `\\audit.invalid\split\via-vpn.json`} {
		got := filemanager.BasePath(ctx, ruleSetPath(candidate))
		if !strings.EqualFold(filepath.Clean(got), filepath.Clean(candidate)) {
			t.Errorf("C1-14: ожидался исходный абсолютный путь %q, получено %q", candidate, got)
		}
	}
}

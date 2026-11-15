package rescuestats

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type fakeLane struct {
	now string
	all []string
}

func (f *fakeLane) Now() string   { return f.now }
func (f *fakeLane) All() []string { return f.all }
func (f *fakeLane) SelectOutbound(tag string) bool {
	for _, m := range f.all {
		if m == tag {
			f.now = tag
			return true
		}
	}
	return false
}

func copyTag(server string, n int) string { return fmt.Sprintf("%s #%d", server, n) }

func TestSyncLanes(t *testing.T) {
	// Полоса 0: копии обоих серверов; полоса 1: копия A и endpoint W без копии.
	l0 := &fakeLane{now: "A #0", all: []string{"A #0", "B #0"}}
	l1 := &fakeLane{now: "A #1", all: []string{"A #1", "W"}}
	lanes := []laneGroup{l0, l1, nil}

	if n := syncLanes(lanes, "A", copyTag); n != 0 {
		t.Fatalf("уже на A, а переключено %d", n)
	}
	if n := syncLanes(lanes, "B", copyTag); n != 1 || l0.now != "B #0" || l1.now != "A #1" {
		t.Fatalf("B: переключено %d, полосы %q %q", n, l0.now, l1.now)
	}
	if n := syncLanes(lanes, "W", copyTag); n != 1 || l1.now != "W" || l0.now != "B #0" {
		t.Fatalf("W: переключено %d, полосы %q %q", n, l0.now, l1.now)
	}
}

func TestLeafOf(t *testing.T) {
	outs := map[string]adapter.Outbound{
		"select": &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, now: "lowest"},
		"lowest": &fakeGroup{fakeOutbound: fakeOutbound{tag: "lowest"}, now: "B"},
		"B":      &fakeOutbound{tag: "B", typ: "vless"},
	}
	lookup := func(tag string) (adapter.Outbound, bool) { o, ok := outs[tag]; return o, ok }
	if got := leafOf(lookup, "select"); got != "B" {
		t.Fatalf("leafOf = %q, ждали B", got)
	}
	if got := leafOf(lookup, "нет такого"); got != "нет такого" {
		t.Fatalf("leafOf неизвестного = %q", got)
	}
}

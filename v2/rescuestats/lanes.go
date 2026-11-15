package rescuestats

// LaneSync держит полосы групп (config/lanes.go) на том же сервере, что выбран в `select`.
//
// Полоса — свой селектор из копий серверов. Пользователь или сторож меняет `select`; LaneSync
// раз в полсекунды смотрит, какой сервер выбран на самом деле (через группы «Авто» до сервера),
// и ставит в каждой полосе копию этого сервера. Сервера без копии (endpoint) полоса берёт сам.

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
)

type LaneSyncOptions struct {
	SelectTag string
	Lanes     []string                          // теги селекторов полос по номерам
	CopyTag   func(server string, n int) string // тег копии сервера в полосе n
	Interval  time.Duration                     // 0 — полсекунды
	Log       func(string)
}

type LaneSync struct {
	opts LaneSyncOptions
	svc  *daemon.StartedService
	mu   sync.Mutex
	stop chan struct{}
	done chan struct{}
}

var _ adapter.LifecycleService = (*LaneSync)(nil)

func NewLaneSync(opts LaneSyncOptions) *LaneSync {
	if opts.Interval <= 0 {
		opts.Interval = 500 * time.Millisecond
	}
	return &LaneSync{opts: opts}
}

func (l *LaneSync) Bind(svc *daemon.StartedService) { l.svc = svc }
func (l *LaneSync) Name() string                    { return "rescue-lanes" }

// laneGroup — то, что нужно от селектора полосы.
type laneGroup interface {
	Now() string
	All() []string
	SelectOutbound(tag string) bool
}

// leafOf — сервер, к которому сейчас ведёт выход tag: группы проходим по Now().
func leafOf(lookup func(string) (adapter.Outbound, bool), tag string) string {
	for i := 0; i < 8; i++ {
		ob, ok := lookup(tag)
		if !ok {
			return tag
		}
		group, isGroup := ob.(adapter.OutboundGroup)
		if !isGroup || group.Now() == "" {
			return tag
		}
		tag = group.Now()
	}
	return tag
}

// syncLanes ставит в каждой полосе копию сервера server (или сам server, если он в полосе
// без копии). Возвращает число переключённых полос.
func syncLanes(lanes []laneGroup, server string, copyTag func(string, int) string) int {
	switched := 0
	for n, lane := range lanes {
		if lane == nil {
			continue
		}
		want := ""
		cp := copyTag(server, n)
		for _, m := range lane.All() {
			if m == cp {
				want = cp
				break
			}
			if m == server {
				want = server
			}
		}
		if want == "" || lane.Now() == want {
			continue
		}
		if lane.SelectOutbound(want) {
			switched++
		}
	}
	return switched
}

func (l *LaneSync) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStarted || l.svc == nil || len(l.opts.Lanes) == 0 {
		return nil
	}
	inst := l.svc.Instance()
	if inst == nil || inst.Box() == nil {
		return nil
	}
	outbounds := inst.Box().Outbound()
	lanes := make([]laneGroup, len(l.opts.Lanes))
	found := false
	for n, tag := range l.opts.Lanes {
		if ob, ok := outbounds.Outbound(tag); ok {
			if g, ok := ob.(laneGroup); ok {
				lanes[n] = g
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	tick := func() {
		server := leafOf(outbounds.Outbound, l.opts.SelectTag)
		if n := syncLanes(lanes, server, l.opts.CopyTag); n > 0 && l.opts.Log != nil {
			l.opts.Log("полосы групп: сервер " + server)
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopLocked()
	stop, done := make(chan struct{}), make(chan struct{})
	l.stop, l.done = stop, done
	tick()
	go func() {
		defer close(done)
		t := time.NewTicker(l.opts.Interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				tick()
			}
		}
	}()
	return nil
}

func (l *LaneSync) stopLocked() {
	if l.stop != nil {
		close(l.stop)
		<-l.done
		l.stop, l.done = nil, nil
	}
}

func (l *LaneSync) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopLocked()
	return nil
}

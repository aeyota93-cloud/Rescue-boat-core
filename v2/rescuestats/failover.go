package rescuestats

// Автопереключение «основной → запасной» (docs/rescue-failover.md).
//
// Сторож — служба ядра (adapter.LifecycleService) рядом с Collector и Comparer: стартует, когда
// экземпляр sing-box запущен целиком, и останавливается вместе с ним. Раз в 30 с проверяет
// основной сервер (первый тег выхода `select`, не считая групп) urltest'ом прямо через его выход;
// 3 неудачи подряд — переключает `select` на следующий живой запасной, 3 удачи основного подряд
// при активном запасном — возвращает основной. Переключение — Selector.SelectOutbound, как ручной
// выбор через clash API: выход `select` строится с interrupt_exist_connections, старые соединения
// рвутся.
//
// Логика решений — failoverMachine (без IO), проверка и тикер внедряются (тесты).

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/daemon"
)

const (
	FailoverInterval  = 30 * time.Second
	FailoverTimeout   = 5 * time.Second
	FailoverThreshold = 3
	KindFailover      = "failover"

	FailoverMsgToBackup  = "основной не отвечает 3 раза подряд"
	FailoverMsgToPrimary = "основной снова отвечает"
)

type FailoverOptions struct {
	StatsDir  string // rescue-stats-dir: куда писать событие failover (пусто — не пишем)
	TestURL   string // connection-test-url
	SelectTag string // выход-селектор (config.OutboundSelectTag)
	Log       func(msg string)
	Now       func() time.Time
}

// --- конечный автомат ---

// failoverMachine решает, куда переключать. Индекс 0 — основной, 1.. — запасные по порядку.
type failoverMachine struct {
	n           int
	active      int
	primaryFail int // неудач основного подряд
	primaryOK   int // удач основного подряд (считаются, пока активен запасной)
	activeFail  int // неудач активного запасного подряд
}

type failoverDecision struct {
	To  int // куда переключить; -1 — ничего не делать
	Msg string
}

var failoverNone = failoverDecision{To: -1}

func newFailoverMachine(n int) *failoverMachine { return &failoverMachine{n: n} }

// reset — начать с основного (селектор указывает не туда, куда ставил сторож).
func (m *failoverMachine) reset() {
	m.active, m.primaryFail, m.primaryOK, m.activeFail = 0, 0, 0, 0
}

// tick — одна проверка. check(i) проверяет сервер i; вызывается только по необходимости:
// основной — всегда, активный запасной — пока он активен, остальные запасные — при выборе.
func (m *failoverMachine) tick(check func(i int) bool) failoverDecision {
	if m.n < 2 {
		return failoverNone
	}
	primaryAlive := check(0)
	if primaryAlive {
		m.primaryFail = 0
		m.primaryOK++
	} else {
		m.primaryFail++
		m.primaryOK = 0
	}
	if m.active == 0 {
		m.primaryOK = 0
		if m.primaryFail < FailoverThreshold {
			return failoverNone
		}
		// Следующий живой запасной; живых нет — остаёмся на основном и пробуем на следующей проверке.
		for i := 1; i < m.n; i++ {
			if check(i) {
				m.active, m.activeFail = i, 0
				return failoverDecision{To: i, Msg: FailoverMsgToBackup}
			}
		}
		return failoverNone
	}
	if m.primaryOK >= FailoverThreshold {
		m.reset()
		return failoverDecision{To: 0, Msg: FailoverMsgToPrimary}
	}
	if check(m.active) {
		m.activeFail = 0
		return failoverNone
	}
	m.activeFail++
	if m.activeFail < FailoverThreshold {
		return failoverNone
	}
	// Активный запасной тоже умер: следующий живой запасной по кругу (основной по-прежнему мёртв
	// или ещё не набрал 3 удачи). Живых нет — остаёмся где есть.
	for k := 1; k < m.n-1; k++ {
		i := 1 + (m.active-1+k)%(m.n-1)
		if check(i) {
			m.active, m.activeFail = i, 0
			return failoverDecision{To: i, Msg: FailoverMsgToBackup}
		}
	}
	return failoverNone
}

// --- служба ядра ---

// failoverSelector — то, что нужно сторожу от выхода `select` (group.Selector).
type failoverSelector interface {
	Now() string
	SelectOutbound(tag string) bool
}

type Failover struct {
	opts   FailoverOptions
	svc    *daemon.StartedService
	access sync.Mutex
	active *failoverRun
}

var _ adapter.LifecycleService = (*Failover)(nil)

func NewFailover(opts FailoverOptions) *Failover {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Failover{opts: opts}
}

func (f *Failover) Bind(svc *daemon.StartedService) { f.svc = svc }

func (f *Failover) Name() string { return "rescue-failover" }

func (f *Failover) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStarted || f.svc == nil {
		return nil
	}
	inst := f.svc.Instance()
	if inst == nil || inst.Box() == nil {
		return nil
	}
	outbounds := inst.Box().Outbound()
	ob, ok := outbounds.Outbound(f.opts.SelectTag)
	if !ok {
		return nil
	}
	sel, ok := ob.(failoverSelector)
	group, isGroup := ob.(adapter.OutboundGroup)
	if !ok || !isGroup {
		return nil
	}
	servers := failoverServers(outbounds, group.All())
	link := f.opts.TestURL
	if link == "" {
		link = defaultProbeURL
	}
	check := func(ctx context.Context, tag string) bool {
		dialer, ok := outbounds.Outbound(tag)
		if !ok {
			return false
		}
		ctx, cancel := context.WithTimeout(ctx, FailoverTimeout)
		defer cancel()
		ms, err := urltest.URLTest(ctx, link, dialer)
		return err == nil && ms > 0
	}
	r := newFailoverRun(f.opts, sel, servers, check, newRealTicker)
	if r == nil {
		return nil // один сервер — сторож не нужен
	}
	f.access.Lock()
	old := f.active
	f.active = r
	f.access.Unlock()
	if old != nil {
		old.stop()
	}
	r.start()
	return nil
}

// Close останавливает сторожа. Можно звать повторно.
func (f *Failover) Close() error {
	f.access.Lock()
	r := f.active
	f.active = nil
	f.access.Unlock()
	if r != nil {
		r.stop()
	}
	return nil
}

// Running — запущен ли сторож (для тестов и диагностики).
func (f *Failover) Running() bool {
	f.access.Lock()
	defer f.access.Unlock()
	return f.active != nil
}

// failoverServers — теги серверов из выхода `select` по порядку, без групп (lowest, balance…).
func failoverServers(outbounds adapter.OutboundManager, tags []string) []string {
	var servers []string
	for _, tag := range tags {
		ob, ok := outbounds.Outbound(tag)
		if !ok {
			continue
		}
		if _, isGroup := ob.(adapter.OutboundGroup); isGroup {
			continue
		}
		servers = append(servers, tag)
	}
	return servers
}

type failoverTicker func(d time.Duration) (<-chan time.Time, func())

func newRealTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// failoverRun — один запуск сторожа.
type failoverRun struct {
	opts    FailoverOptions
	sel     failoverSelector
	servers []string
	check   func(ctx context.Context, tag string) bool
	ticker  failoverTicker
	store   *Store
	machine *failoverMachine
	cycled  func() // тесты: после каждой проверки

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// newFailoverRun возвращает nil, если серверов меньше двух.
func newFailoverRun(opts FailoverOptions, sel failoverSelector, servers []string, check func(context.Context, string) bool, ticker failoverTicker) *failoverRun {
	if sel == nil || len(servers) < 2 {
		return nil
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	r := &failoverRun{
		opts:    opts,
		sel:     sel,
		servers: servers,
		check:   check,
		ticker:  ticker,
		machine: newFailoverMachine(len(servers)),
	}
	if opts.StatsDir != "" {
		r.store = NewStore(opts.StatsDir, opts.Now)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return r
}

func (r *failoverRun) start() {
	// Селектор указывает не на основной (по умолчанию — balance, или выбран вручную) — начинаем
	// с основного.
	if r.sel.Now() != r.servers[0] {
		r.sel.SelectOutbound(r.servers[0])
		r.logf("автопереключение: начинаем с основного " + r.servers[0])
	}
	c, stopTicker := r.ticker(FailoverInterval)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer stopTicker()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-c:
			}
			r.cycle()
			if r.cycled != nil {
				r.cycled()
			}
		}
	}()
}

func (r *failoverRun) stop() {
	r.once.Do(func() {
		r.cancel()
		r.wg.Wait()
		if r.store != nil {
			r.store.Close()
		}
	})
}

// cycle — одна проверка и, если надо, переключение.
func (r *failoverRun) cycle() {
	// Селектор переставили мимо сторожа (вручную) — считаем, что начинаем с основного,
	// сам выбор не трогаем, пока не понадобится переключение.
	if r.sel.Now() != r.servers[r.machine.active] {
		r.machine.reset()
	}
	results := make(map[int]bool)
	d := r.machine.tick(func(i int) bool {
		if ok, done := results[i]; done {
			return ok
		}
		if r.ctx.Err() != nil {
			return false
		}
		ok := r.check(r.ctx, r.servers[i])
		results[i] = ok
		return ok
	})
	if d.To < 0 || r.ctx.Err() != nil {
		// При остановке посреди проверки решения не применяем: неудачи могли быть из-за отмены.
		if d.To >= 0 {
			r.machine.reset()
		}
		return
	}
	tag := r.servers[d.To]
	if !r.sel.SelectOutbound(tag) {
		r.machine.reset()
		return
	}
	r.logf("автопереключение: " + d.Msg + " → " + tag)
	if r.store != nil {
		r.store.AddError(ErrorRecord{
			T:     r.opts.Now().UnixMilli(),
			Kind:  KindFailover,
			Host:  tag,
			Route: RouteVPN,
			Msg:   d.Msg,
		})
		r.store.Flush(true)
	}
}

func (r *failoverRun) logf(msg string) {
	if r.opts.Log != nil {
		r.opts.Log(msg)
	}
}

package rescuestats

// Сторож v2: при старте выбирает самый быстрый рабочий выход (TCP и UDP).
// Затем проверяет только активный раз в 5 с. Переход — после 25 с без удачи
// и минимум четырёх неудач подряд, с повторной проверкой всех выходов.
// Машиной владеет один цикл; рабочие горутины возвращают результаты с поколением.

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	N "github.com/sagernet/sing/common/network"
)

const (
	FailoverInterval   = 5 * time.Second
	FailoverTimeout    = 4 * time.Second
	FailoverWindow     = 25 * time.Second
	FailoverThreshold  = 4
	FailoverCredit     = 25 * time.Second
	failoverPause      = 15 * time.Second
	failoverWallPause  = 10 * time.Second
	failoverEqualDelay = 5 * time.Millisecond
	failoverParallel   = 8
	KindFailover       = "failover"
	FailoverMsgStart   = "выбран самый быстрый рабочий"
	FailoverMsgBroken  = "сервер не отвечает 25 с"
)

// заменяется на ProbeUDP при слиянии ветки failover-v2-udp
var failoverUDPCheck func(ctx context.Context, d N.Dialer) error

type FailoverOptions struct {
	StatsDir  string
	TestURL   string
	SelectTag string
	Log       func(msg string)
	Now       func() time.Time
}

type failoverResult struct {
	OK       bool
	Delay    time.Duration
	Canceled bool
}

type failoverProbe func(ctx context.Context, tag string) failoverResult

type failoverDecision struct{ From, To, Msg string }

type failoverBatch struct {
	generation uint64
	from       string
	tags       []string
	results    map[string]failoverResult
}

type failoverReply struct {
	generation uint64
	tag        string
	result     failoverResult
}

// Машина решений не обращается к часам, сети и селектору.
type failoverMachine struct {
	servers                    []string
	active                     string
	starting, searching        bool
	lastOK, switched, prevTick time.Time
	failures                   int
	generation                 uint64
	pending                    *failoverBatch
}

func newFailoverMachine(servers []string, active string, now time.Time) *failoverMachine {
	return &failoverMachine{servers: servers, active: active, starting: true, lastOK: now, prevTick: now}
}

func (m *failoverMachine) resetWindow(now time.Time) {
	m.lastOK, m.failures, m.searching = now, 0, false
	m.generation++
	m.pending = nil
}

// Проверяем паузу и перед результатом: он может прийти раньше первого тика после сна.
func (m *failoverMachine) observe(now time.Time, selected string, tick bool) bool {
	mono := now.Sub(m.prevTick)
	wall := now.Round(0).Sub(m.prevTick.Round(0))
	paused := mono > failoverPause || wall-mono > failoverWallPause
	changed := selected != m.active
	if paused || changed {
		m.resetWindow(now)
		m.prevTick = now
		if changed {
			m.active, m.starting, m.switched = selected, false, now
		}
	}
	if tick {
		m.prevTick = now
	}
	return paused || changed
}

func (m *failoverMachine) next() *failoverBatch {
	if m.pending != nil {
		return nil
	}
	tags := []string{m.active}
	if m.starting || m.searching {
		tags = append([]string(nil), m.servers...)
		found := false
		for _, tag := range tags {
			if tag == m.active {
				found = true
			}
		}
		if !found && !m.starting {
			tags = append(tags, m.active)
		}
	}
	m.generation++
	m.pending = &failoverBatch{generation: m.generation, from: m.active, tags: tags, results: make(map[string]failoverResult)}
	return m.pending
}

func (m *failoverMachine) broken(now time.Time) bool {
	return m.failures >= FailoverThreshold && now.Sub(m.lastOK) >= FailoverWindow &&
		(m.switched.IsZero() || now.Sub(m.switched) >= FailoverCredit)
}

// follow означает: порог достигнут, подтверждающую партию нужно начать сразу.
func (m *failoverMachine) receive(now time.Time, reply failoverReply) (decision failoverDecision, follow bool) {
	b := m.pending
	if b == nil || reply.generation != b.generation {
		return
	}
	if _, duplicate := b.results[reply.tag]; duplicate {
		return
	}
	b.results[reply.tag] = reply.result
	if reply.tag == m.active && reply.result.OK && !reply.result.Canceled {
		m.lastOK, m.failures = now, 0
	}
	if len(b.results) != len(b.tags) {
		return
	}
	m.pending = nil
	for _, result := range b.results {
		if result.Canceled {
			return
		}
	}
	activeOK := b.results[m.active].OK
	if !m.starting && !m.searching {
		if !activeOK {
			m.failures++
		}
		if m.broken(now) {
			m.searching, follow = true, true
		}
		return
	}
	if !m.starting && activeOK {
		m.searching = false
		return
	}
	// Равенство считаем от общего минимума, без цепочки попарных сравнений.
	var minimum time.Duration
	found := false
	for _, tag := range b.tags {
		result := b.results[tag]
		if result.OK && (!found || result.Delay < minimum) {
			minimum, found = result.Delay, true
		}
	}
	if !found {
		return
	}
	for _, tag := range b.tags {
		result := b.results[tag]
		if !result.OK || result.Delay-minimum > failoverEqualDelay {
			continue
		}
		if tag == m.active {
			m.starting, m.searching = false, false
			return
		}
		msg := FailoverMsgBroken
		if m.starting {
			msg = FailoverMsgStart
		}
		return failoverDecision{From: b.from, To: tag, Msg: msg}, false
	}
	return
}

func (m *failoverMachine) switchedTo(tag string, now time.Time) {
	m.resetWindow(now)
	m.active, m.starting, m.switched = tag, false, now
}

// TCP и UDP используют общий deadline; отмена владельцем не считается отказом.
func probeFailover(ctx context.Context, link string, d N.Dialer, tcp probeFunc, udp func(context.Context, N.Dialer) error) failoverResult {
	ctx, cancel := context.WithTimeout(ctx, FailoverTimeout)
	defer cancel()
	var delay time.Duration
	var tcpErr, udpErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); delay, tcpErr = tcp(ctx, link, d) }()
	go func() {
		defer wg.Done()
		if udp != nil {
			udpErr = udp(ctx, d)
		}
	}()
	wg.Wait()
	return failoverResult{OK: tcpErr == nil && udpErr == nil && ctx.Err() == nil, Delay: delay, Canceled: ctx.Err() == context.Canceled}
}

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
func (f *Failover) Name() string                    { return "rescue-failover" }

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
	check := func(ctx context.Context, tag string) failoverResult {
		dialer, exists := outbounds.Outbound(tag)
		if !exists {
			return failoverResult{Canceled: ctx.Err() == context.Canceled}
		}
		return probeFailover(ctx, link, dialer, urlTestProbe, failoverUDPCheck)
	}
	r := newFailoverRun(f.opts, sel, servers, check, newRealTicker)
	if r == nil {
		return nil
	}
	f.access.Lock()
	defer f.access.Unlock()
	if f.active != nil {
		f.active.stop()
	}
	f.active = r
	r.start()
	return nil
}

// Close ждёт цикл и все рабочие горутины. Повторный вызов безопасен.
func (f *Failover) Close() error {
	f.access.Lock()
	defer f.access.Unlock()
	if f.active != nil {
		f.active.stop()
		f.active = nil
	}
	return nil
}

func (f *Failover) Running() bool {
	f.access.Lock()
	defer f.access.Unlock()
	return f.active != nil
}

// Серверы по порядку подписки, без групп и дублей.
func failoverServers(outbounds adapter.OutboundManager, tags []string) []string {
	var servers []string
	seen := make(map[string]bool)
	for _, tag := range tags {
		ob, ok := outbounds.Outbound(tag)
		if !ok || seen[tag] {
			continue
		}
		if _, isGroup := ob.(adapter.OutboundGroup); isGroup {
			continue
		}
		seen[tag] = true
		servers = append(servers, tag)
	}
	return servers
}

type failoverTicker func(d time.Duration) (<-chan time.Time, func())

func newRealTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

type failoverRun struct {
	opts        FailoverOptions
	sel         failoverSelector
	servers     []string
	check       failoverProbe
	ticker      failoverTicker
	store       *Store
	machine     *failoverMachine
	processed   func() // Тесты: событие обработано владельцем.
	ctx         context.Context
	cancel      context.CancelFunc
	wg, workers sync.WaitGroup
	once        sync.Once
	slots       chan struct{}
	replies     chan failoverReply
}

func newFailoverRun(opts FailoverOptions, sel failoverSelector, servers []string, check failoverProbe, ticker failoverTicker) *failoverRun {
	seen := make(map[string]bool)
	var unique []string
	for _, tag := range servers {
		if !seen[tag] {
			seen[tag] = true
			unique = append(unique, tag)
		}
	}
	if sel == nil || len(unique) < 2 {
		return nil
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	r := &failoverRun{opts: opts, sel: sel, servers: unique, check: check, ticker: ticker,
		slots: make(chan struct{}, failoverParallel), replies: make(chan failoverReply)}
	if opts.StatsDir != "" {
		r.store = NewStore(opts.StatsDir, opts.Now)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return r
}

func (r *failoverRun) launch(b *failoverBatch) context.CancelFunc {
	ctx, cancel := context.WithTimeout(r.ctx, FailoverTimeout)
	for _, tag := range b.tags {
		r.workers.Add(1)
		go func(tag string) {
			defer r.workers.Done()
			result := failoverResult{Canceled: true}
			select {
			case r.slots <- struct{}{}:
				if ctx.Err() == nil {
					result = r.check(ctx, tag)
				} else {
					result.Canceled = ctx.Err() == context.Canceled
				}
				<-r.slots
			case <-ctx.Done():
				result.Canceled = ctx.Err() == context.Canceled
			}
			select {
			case r.replies <- failoverReply{generation: b.generation, tag: tag, result: result}:
			case <-r.ctx.Done():
			}
		}(tag)
	}
	return cancel
}

func (r *failoverRun) start() {
	initial := r.sel.Now()
	c, stopTicker := r.ticker(FailoverInterval)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.workers.Wait()
		defer stopTicker()
		now := r.opts.Now()
		r.machine = newFailoverMachine(r.servers, initial, now)
		if selected := r.sel.Now(); selected != initial {
			r.machine.observe(now, selected, false)
		} else if initial != r.servers[0] && r.ctx.Err() == nil {
			// До стартовой пробы — первый сервер подписки, как в договоре v2.
			// Это начальное состояние, событие выбора самого быстрого ещё не пишем.
			if r.sel.SelectOutbound(r.servers[0]) {
				r.machine.active = r.servers[0]
			}
		}
		cancelBatch := r.launch(r.machine.next())
		defer func() { cancelBatch() }()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-c:
				now := r.opts.Now()
				if r.machine.observe(now, r.sel.Now(), true) {
					cancelBatch()
				}
				if b := r.machine.next(); b != nil {
					cancelBatch()
					cancelBatch = r.launch(b)
				}
			case reply := <-r.replies:
				if r.ctx.Err() != nil {
					return
				}
				now := r.opts.Now()
				if r.machine.observe(now, r.sel.Now(), false) {
					cancelBatch()
					cancelBatch = r.launch(r.machine.next())
				}
				decision, follow := r.machine.receive(now, reply)
				r.apply(decision)
				if follow {
					cancelBatch()
					cancelBatch = r.launch(r.machine.next())
				}
			}
			if r.processed != nil {
				r.processed()
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

func (r *failoverRun) apply(d failoverDecision) {
	if d.To == "" || d.To == d.From || r.ctx.Err() != nil {
		return
	}
	if selected := r.sel.Now(); selected != d.From {
		r.machine.observe(r.opts.Now(), selected, false)
		return
	}
	// Между Now и Swap остаётся гонка с clash API: условного выбора в sing-box нет,
	// подмодуль не меняем. Приложение после ручного выбора выключает авто; внешний
	// выбор принимается на следующем событии. Окно — микросекунды: возможен выбор
	// рабочего сервера вместо ручного, пользователь выберет снова. A→B→A безвредна.
	if !r.sel.SelectOutbound(d.To) {
		return
	}
	now := r.opts.Now()
	r.machine.switchedTo(d.To, now)
	if r.opts.Log != nil {
		r.opts.Log("автопереключение: " + d.Msg + " → " + d.To)
	}
	if r.store != nil {
		r.store.AddError(ErrorRecord{T: now.UnixMilli(), Kind: KindFailover, Host: d.To, Route: RouteVPN, Msg: d.Msg})
		r.store.Flush(true)
	}
}

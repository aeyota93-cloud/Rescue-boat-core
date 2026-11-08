package rescuestats

// Сторож v2: при старте выбирает самый быстрый рабочий выход (TCP и UDP).
// Затем проверяет только активный раз в 5 с. Переход — после 25 с без удачи
// и минимум четырёх неудач подряд, с повторной проверкой всех выходов.
// Машиной владеет один цикл; рабочие горутины возвращают результаты с поколением.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	N "github.com/sagernet/sing/common/network"
)

const (
	FailoverInterval      = 5 * time.Second
	FailoverTimeout       = 4 * time.Second
	FailoverWindow        = 25 * time.Second
	FailoverThreshold     = 4
	FailoverCredit        = 25 * time.Second
	failoverPause         = 15 * time.Second
	failoverWallPause     = 10 * time.Second
	failoverEqualDelay    = 5 * time.Millisecond
	failoverParallel      = 8
	failoverStartParallel = 4
	failoverOrphanLimit   = 2
	failoverStopTimeout   = time.Second
	KindFailover          = "failover"
	FailoverMsgStart      = "выбран самый быстрый рабочий"
	FailoverMsgBroken     = "сервер не отвечает 25 с"
)

// UDP-часть пробы сервера (DNS через выход, probe_udp.go); тесты подменяют.
var failoverUDPCheck func(ctx context.Context, d N.Dialer) error = ProbeUDP

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

// TCP и UDP используют общий deadline. Владелец собирает результат по сроку,
// а эта горутина ждёт обе части, чтобы учитывать живых сирот до конца.
func probeFailover(ctx context.Context, link string, d N.Dialer, tcp probeFunc, udp func(context.Context, N.Dialer) error) failoverResult {
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
	r := newFailoverRun(inst.Context(), f.opts, sel, servers, check, newRealTicker)
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

// Close ждёт цикл, затем даёт сиротам до секунды. Повторный вызов безопасен.
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
	opts      FailoverOptions
	sel       failoverSelector
	servers   []string
	check     failoverProbe
	ticker    failoverTicker
	store     *Store
	machine   *failoverMachine
	processed func() // Тесты: событие обработано владельцем.
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	once      sync.Once
	replies   chan failoverReply
	timeout   func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	workers   *failoverWorkers
	wave      *failoverWave
}

// Реестр живёт отдельно от машины. Рабочие горутины знают только его и свой результат.
type failoverWork struct {
	tag    string
	orphan bool
}

type failoverWorkers struct {
	mu      sync.Mutex
	live    map[*failoverWork]struct{}
	orphans map[string]int
	idle    chan struct{}
}

func newFailoverWorkers() *failoverWorkers {
	idle := make(chan struct{})
	close(idle)
	return &failoverWorkers{live: make(map[*failoverWork]struct{}), orphans: make(map[string]int), idle: idle}
}

func (w *failoverWorkers) begin(tag string) *failoverWork {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.orphans[tag] >= failoverOrphanLimit {
		return nil
	}
	if len(w.live) == 0 {
		w.idle = make(chan struct{})
	}
	work := &failoverWork{tag: tag}
	w.live[work] = struct{}{}
	return work
}

func (w *failoverWorkers) finish(work *failoverWork) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.live, work)
	if work.orphan {
		w.orphans[work.tag]--
		if w.orphans[work.tag] == 0 {
			delete(w.orphans, work.tag)
		}
	}
	if len(w.live) == 0 {
		close(w.idle)
	}
}

func (w *failoverWorkers) detach(work *failoverWork) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, alive := w.live[work]; alive && !work.orphan {
		work.orphan = true
		w.orphans[work.tag]++
	}
}

func (w *failoverWorkers) waiting() (<-chan struct{}, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.idle, len(w.live)
}

type failoverWave struct {
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
	pending    map[string]*failoverWork
	queue      []string
	limit      int
}

func newFailoverRun(parent context.Context, opts FailoverOptions, sel failoverSelector, servers []string, check failoverProbe, ticker failoverTicker) *failoverRun {
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
		timeout: context.WithTimeout, workers: newFailoverWorkers(), replies: make(chan failoverReply, 4*len(unique)+8)}
	if opts.StatsDir != "" {
		r.store = NewStore(opts.StatsDir, opts.Now)
	}
	r.ctx, r.cancel = context.WithCancel(parent)
	return r
}

func runFailoverProbe(ctx context.Context, check failoverProbe, workers *failoverWorkers, work *failoverWork, generation uint64, replies chan<- failoverReply) {
	result := failoverResult{Canceled: ctx.Err() == context.Canceled}
	if ctx.Err() == nil {
		result = check(ctx, work.tag)
	}
	workers.finish(work)
	// Сирота не задерживает остановку, даже если владелец уже ушёл.
	select {
	case replies <- failoverReply{generation, work.tag, result}:
	default:
	}
}

func (r *failoverRun) launch(b *failoverBatch) {
	if b == nil || r.ctx.Err() != nil {
		return
	}
	limit := failoverParallel
	if r.machine.starting {
		limit = failoverStartParallel
	}
	r.wave = &failoverWave{generation: b.generation, queue: b.tags, limit: limit}
	r.launchWave()
}

func (r *failoverRun) launchWave() {
	w := r.wave
	if w == nil {
		return
	}
	if r.ctx.Err() != nil {
		r.cancelWave()
		return
	}
	if len(w.queue) == 0 {
		r.wave = nil
		return
	}
	n := min(w.limit, len(w.queue))
	tags := w.queue[:n]
	w.queue = w.queue[n:]
	w.ctx, w.cancel = r.timeout(r.ctx, FailoverTimeout)
	w.pending = make(map[string]*failoverWork, n)
	for _, tag := range tags {
		if r.ctx.Err() != nil {
			return
		}
		work := r.workers.begin(tag)
		w.pending[tag] = work
		if work == nil {
			r.replies <- failoverReply{generation: w.generation, tag: tag}
			continue
		}
		go runFailoverProbe(w.ctx, r.check, r.workers, work, w.generation, r.replies)
	}
}

func (r *failoverRun) cancelWave() {
	if w := r.wave; w != nil {
		if w.cancel != nil {
			w.cancel()
		}
		for _, work := range w.pending {
			if work != nil {
				r.workers.detach(work)
			}
		}
		r.wave = nil
	}
}

func (r *failoverRun) receive(reply failoverReply) {
	if r.ctx.Err() != nil {
		return
	}
	b := r.machine.pending
	starting := r.machine.starting
	now := r.opts.Now()
	if r.ctx.Err() != nil {
		return
	}
	decision, follow := r.machine.receive(now, reply)
	r.apply(decision)
	if b != nil && reply.generation == b.generation && len(b.results) == len(b.tags) && starting {
		r.logStartup(b)
	}
	if follow {
		r.cancelWave()
		r.launch(r.machine.next())
	}
}

func (r *failoverRun) logStartup(b *failoverBatch) {
	if r.opts.Log == nil || r.ctx.Err() != nil {
		return
	}
	var parts []string
	for _, tag := range b.tags {
		result := b.results[tag]
		status := "неудача"
		if result.OK && !result.Canceled {
			status = "ok"
		}
		parts = append(parts, fmt.Sprintf("%s: %s, %d мс", tag, status, result.Delay.Milliseconds()))
	}
	selected := r.sel.Now()
	if r.ctx.Err() == nil {
		r.opts.Log("стартовая проверка: " + strings.Join(parts, "; ") + "; выбран: " + selected)
	}
}

func (r *failoverRun) expireWave() {
	w := r.wave
	if w == nil || r.ctx.Err() != nil {
		return
	}
	w.cancel()
	for tag, work := range w.pending {
		if work != nil {
			r.workers.detach(work)
		}
		r.receive(failoverReply{w.generation, tag, failoverResult{Delay: FailoverTimeout}})
	}
	if r.wave == w {
		r.launchWave()
	}
}

func (r *failoverRun) start() {
	initial := r.sel.Now()
	c, stopTicker := r.ticker(FailoverInterval)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer stopTicker()
		defer r.cancelWave()
		if r.ctx.Err() != nil {
			return
		}
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
		r.launch(r.machine.next())
		for {
			if r.ctx.Err() != nil {
				return
			}
			var deadline <-chan struct{}
			if r.wave != nil {
				deadline = r.wave.ctx.Done()
			}
			select {
			case <-r.ctx.Done():
				return
			case <-c:
				if r.ctx.Err() != nil {
					return
				}
				now := r.opts.Now()
				if r.machine.observe(now, r.sel.Now(), true) {
					r.cancelWave()
				} else if r.wave != nil && r.wave.ctx.Err() != nil {
					r.expireWave()
				}
				if b := r.machine.next(); b != nil {
					r.launch(b)
				}
			case <-deadline:
				if r.ctx.Err() != nil {
					return
				}
				if r.machine.observe(r.opts.Now(), r.sel.Now(), false) {
					r.cancelWave()
					r.launch(r.machine.next())
				} else {
					r.expireWave()
				}
			case reply := <-r.replies:
				if r.ctx.Err() != nil {
					return
				}
				now := r.opts.Now()
				if r.machine.observe(now, r.sel.Now(), false) {
					r.cancelWave()
					r.launch(r.machine.next())
				}
				if r.wave != nil && r.wave.ctx.Err() != nil {
					r.expireWave()
				}
				w := r.wave
				r.receive(reply)
				if w != nil && r.wave == w && reply.generation == w.generation {
					delete(w.pending, reply.tag)
					if len(w.pending) == 0 {
						w.cancel()
						r.launchWave()
					}
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
		idle, count := r.workers.waiting()
		if count > 0 {
			ctx, cancel := r.timeout(context.Background(), failoverStopTimeout)
			select {
			case <-idle:
			case <-ctx.Done():
			}
			cancel()
			_, count = r.workers.waiting()
		}
		if r.opts.Log != nil {
			r.opts.Log(fmt.Sprintf("сторож остановлен: осталось сирот — %d", count))
		}
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
	if r.ctx.Err() != nil {
		return
	}
	// Между Now и Swap остаётся гонка с clash API: условного выбора в sing-box нет,
	// подмодуль не меняем. Приложение после ручного выбора выключает авто; внешний
	// выбор принимается на следующем событии. Окно — микросекунды: возможен выбор
	// рабочего сервера вместо ручного, пользователь выберет снова. A→B→A безвредна.
	if !r.sel.SelectOutbound(d.To) {
		return
	}
	if r.ctx.Err() != nil {
		return
	}
	now := r.opts.Now()
	if r.ctx.Err() != nil {
		return
	}
	r.machine.switchedTo(d.To, now)
	if r.opts.Log != nil {
		r.opts.Log("автопереключение: " + d.Msg + " → " + d.To)
	}
	if r.store != nil && r.ctx.Err() == nil {
		r.store.AddError(ErrorRecord{T: now.UnixMilli(), Kind: KindFailover, Host: d.To, Route: RouteVPN, Msg: d.Msg})
		r.store.Flush(true)
	}
}

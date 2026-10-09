package rescuestats

// Сборщик статистики «Шлюпки спасения»: ошибки соединений и замеры качества в файлы для
// приложения (формат — docs/rescue-redesign-contract.md, раздел 1).
//
// Collector — служба ядра (adapter.LifecycleService): стартует и останавливается вместе с
// экземпляром sing-box, в том числе при перезапуске. Пока не запущен, обёртки соединений
// ничего не делают.

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	QualityInterval = time.Minute
	// Сколько помнить закрытое соединение: строка журнала с причиной приходит чуть позже закрытия.
	closedGrace = 5 * time.Second
)

type Options struct {
	Dir            string
	TestURL        string // connection-test-url
	VPNOutbound    string // выбранный VPN-путь (группа selector)
	DirectOutbound string
	NoProbe        bool             // rescue-stats-probe: false — без замеров probe (counters пишутся)
	Now            func() time.Time // для тестов
}

type Collector struct {
	opts   Options
	svc    *daemon.StartedService
	active atomic.Pointer[run]
	access sync.Mutex
	run    *run // подготовлен на стадии Initialize, запущен на Start
}

var (
	_ adapter.LifecycleService  = (*Collector)(nil)
	_ adapter.ConnectionTracker = (*Collector)(nil)
)

// New возвращает nil, если папка не задана: тогда ядро ничего не пишет и не замеряет.
func New(opts Options) *Collector {
	if opts.Dir == "" {
		return nil
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{opts: opts}
}

// Bind — служба ядра, из которой берутся экземпляр sing-box и журнал.
func (c *Collector) Bind(svc *daemon.StartedService) {
	c.svc = svc
}

func (c *Collector) Name() string { return "rescue-stats" }

func (c *Collector) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		// Обёртки соединений должны встать до запуска входов.
		if c.svc == nil {
			return nil
		}
		inst := c.svc.Instance()
		if inst == nil || inst.Box() == nil {
			return nil
		}
		box := inst.Box()
		c.access.Lock()
		c.run = newRun(c.opts, box.Outbound())
		c.access.Unlock()
		box.Router().AppendTracker(c)
	case adapter.StartStateStart:
		c.access.Lock()
		r := c.run
		c.access.Unlock()
		if r == nil {
			return nil
		}
		if err := r.store.Open(); err != nil {
			// Нет папки — работаем без статистики, ядро не останавливаем.
			return nil
		}
		r.start(c.svc)
		c.active.Store(r)
	}
	return nil
}

// Close останавливает горутины и дописывает файлы. Можно звать повторно.
func (c *Collector) Close() error {
	c.access.Lock()
	c.run = nil
	c.access.Unlock()
	if r := c.active.Swap(nil); r != nil {
		r.stop()
	}
	return nil
}

func (c *Collector) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	r := c.active.Load()
	if r == nil {
		return conn
	}
	info := r.register(ctx, metadata, "tcp", matchOutbound)
	return newTrackedConn(conn, info, r)
}

func (c *Collector) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	r := c.active.Load()
	if r == nil {
		return conn
	}
	info := r.register(ctx, metadata, "udp", matchOutbound)
	return newTrackedPacketConn(conn, info, r)
}

// run — один запуск экземпляра ядра.
type run struct {
	opts      Options
	now       func() time.Time
	store     *Store
	outbounds adapter.OutboundManager

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool

	access sync.Mutex
	byID   map[uint32]*connInfo
	udp    map[*connInfo]struct{}
	ended  []*connInfo // закрытые, ждут конца closedGrace
	ownIDs map[uint32]time.Time

	conns    atomic.Int64
	errs     atomic.Int64
	dnsStart atomic.Int64
	dnsFail  atomic.Int64
}

func newRun(opts Options, outbounds adapter.OutboundManager) *run {
	return &run{
		opts:      opts,
		now:       opts.Now,
		store:     NewStore(opts.Dir, opts.Now),
		outbounds: outbounds,
		byID:      make(map[uint32]*connInfo),
		udp:       make(map[*connInfo]struct{}),
		ownIDs:    make(map[uint32]time.Time),
	}
}

func (r *run) start(svc *daemon.StartedService) {
	r.ctx, r.cancel = context.WithCancel(context.Background())
	if svc != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			_ = svc.SubscribeLog(&emptypb.Empty{}, &logStream{ctx: r.ctx, run: r})
		}()
	}
	r.wg.Add(2)
	go r.maintenanceLoop()
	go r.qualityLoop()
}

func (r *run) stop() {
	if !r.closed.CompareAndSwap(false, true) {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	// Незакончившиеся «замирания» открытых UDP-соединений.
	r.access.Lock()
	for info := range r.udp {
		r.finishStall(info)
	}
	r.access.Unlock()
	r.store.Close()
}

func (r *run) register(ctx context.Context, metadata adapter.InboundContext, network string, matchOutbound adapter.Outbound) *connInfo {
	info := newConnInfo(ctx, metadata, network, routeOf(r.outbounds, matchOutbound), r.now())
	r.conns.Add(1)
	r.access.Lock()
	if info.hasLogID {
		r.byID[info.logID] = info
	}
	if network == "udp" {
		r.udp[info] = struct{}{}
	}
	r.access.Unlock()
	return info
}

func (r *run) lookupID(id uint32) *connInfo {
	r.access.Lock()
	defer r.access.Unlock()
	return r.byID[id]
}

func (r *run) isOwnID(id uint32) bool {
	r.access.Lock()
	defer r.access.Unlock()
	_, ok := r.ownIDs[id]
	return ok
}

func (r *run) connClosed(info *connInfo) {
	info.closedAt.CompareAndSwap(0, r.now().UnixNano())
	r.access.Lock()
	r.ended = append(r.ended, info)
	r.access.Unlock()
}

// connError — соединение программы закончилось ошибкой (первая причина побеждает).
func (r *run) connError(info *connInfo, text string, err error) {
	if r.closed.Load() {
		return
	}
	if (err != nil && IsIgnorable(err)) || IsIgnorableText(text) {
		return
	}
	// Ошибка чтения/записи на стороне программы (её адрес в тексте) — это не сеть.
	if info.programAddr != "" && containsAddr(text, info.programAddr) {
		return
	}
	var kind string
	if err != nil {
		kind = Classify(err)
	} else {
		kind = ClassifyText(text)
	}
	if kind == KindEOF && info.down.Load() > 0 {
		return // EOF после данных — обычное закрытие
	}
	if !info.errored.CompareAndSwap(false, true) {
		return
	}
	r.errs.Add(1)
	at := r.now()
	if closed := info.closedAt.Load(); closed != 0 {
		at = time.Unix(0, closed)
	}
	var dur int64
	if est := info.established.Load(); est != 0 {
		dur = at.Sub(time.Unix(0, est)).Milliseconds()
	} else if info.up.Load()+info.down.Load() > 0 {
		dur = at.Sub(info.created).Milliseconds()
	}
	if dur < 0 {
		dur = 0
	}
	r.store.AddError(ErrorRecord{
		T:     at.UnixMilli(),
		Kind:  kind,
		App:   info.app,
		Host:  info.host,
		IP:    info.ip,
		Port:  info.port,
		Net:   info.network,
		Route: info.route,
		DurMs: dur,
		Msg:   CleanMsg(text),
	})
}

func containsAddr(text, addr string) bool {
	for from := 0; addr != ""; {
		j := strings.Index(text[from:], addr)
		if j < 0 {
			return false
		}
		end := from + j + len(addr)
		// «127.0.0.1:5555» не должен совпасть с «127.0.0.1:55556».
		if end == len(text) || text[end] < '0' || text[end] > '9' {
			return true
		}
		from += j + 1
	}
	return false
}

func (r *run) stallRecord(info *connInfo, gap time.Duration) {
	at := r.now()
	r.store.AddError(ErrorRecord{
		T:     at.UnixMilli(),
		Kind:  KindStall,
		App:   info.app,
		Host:  info.host,
		IP:    info.ip,
		Port:  info.port,
		Net:   info.network,
		Route: info.route,
		DurMs: at.Sub(info.created).Milliseconds(),
		GapMs: gap.Milliseconds(),
		Msg:   "no data received for " + gap.Round(time.Millisecond).String() + " while sending",
	})
}

// finishStall — r.access уже взят.
func (r *run) finishStall(info *connInfo) {
	info.stall.Observe(r.now(), info.up.Load(), info.down.Load())
	if gap, ok := info.stall.Finish(); ok {
		r.stallRecord(info, gap)
	}
	delete(r.udp, info)
}

// maintenanceLoop: раз в 250 мс — схлопнутые ошибки в файл, опрос UDP-счётчиков,
// уборка закрытых соединений.
func (r *run) maintenanceLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(StallPoll)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		r.maintain()
	}
}

func (r *run) maintain() {
	now := r.now()
	r.access.Lock()
	for info := range r.udp {
		if info.closedAt.Load() != 0 {
			r.finishStall(info)
			continue
		}
		if gap, ok := info.stall.Observe(now, info.up.Load(), info.down.Load()); ok {
			r.stallRecord(info, gap)
		}
	}
	kept := r.ended[:0]
	for _, info := range r.ended {
		if now.Sub(time.Unix(0, info.closedAt.Load())) < closedGrace {
			kept = append(kept, info)
			continue
		}
		if info.hasLogID && r.byID[info.logID] == info {
			delete(r.byID, info.logID)
		}
	}
	for i := len(kept); i < len(r.ended); i++ {
		r.ended[i] = nil
	}
	r.ended = kept
	for id, until := range r.ownIDs {
		if now.After(until) {
			delete(r.ownIDs, id)
		}
	}
	r.access.Unlock()
	r.store.Flush(false)
}

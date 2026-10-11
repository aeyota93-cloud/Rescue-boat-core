package rescuestats

// «Сравнить пути» (docs/rescue-compare-paths.md): приложение кладёт в папку rescue-compare-dir
// запрос req-<id>.json, ядро меряет цель напрямую и через VPN поочерёдно и пишет (перезаписывает
// по ходу дела) res-<id>.json. Работает независимо от сборщика статистики (Collector).
//
// Службы ядра: Comparer стартует и останавливается вместе с экземпляром sing-box.
// Замеры идут прямо через выходы (direct и VPN), мимо маршрутизатора: правила не участвуют.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/idna"
)

const (
	CompareFormatVersion = 1
	compareScanInterval  = time.Second
	compareMaxQueue      = 30
	compareMaxAge        = time.Hour
	compareDefaultPort   = 443
	compareDefaultCount  = 10
	compareMinCount      = 3
	compareMaxCount      = 30
	compareMeasureTO     = 2 * time.Second
	comparePause         = 300 * time.Millisecond
	compareResolveTO     = 3 * time.Second

	reqPrefix = "req-"
	resPrefix = "res-"
	jsonExt   = ".json"
)

var (
	compareIDRe   = regexp.MustCompile(`^[a-z0-9]{8,32}$`)
	compareHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)*$`)
)

// CompareRequest — запрос приложения (req-<id>.json).
type CompareRequest struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	Target  string `json:"target"`
	Port    int    `json:"port,omitempty"`
	Count   int    `json:"count,omitempty"`
	Created int64  `json:"created,omitempty"`
}

// ComparePath — результат по одной дороге. samples: миллисекунды, null — неудача.
type ComparePath struct {
	Available bool   `json:"available"`
	FirstMS   *int   `json:"first_ms"`
	Samples   []*int `json:"samples"`
	Note      string `json:"note"`
	Estimate  bool   `json:"estimate,omitempty"`
}

type ComparePaths struct {
	Direct *ComparePath `json:"direct"`
	VPN    *ComparePath `json:"vpn"`
}

// CompareResult — ответ ядра (res-<id>.json).
type CompareResult struct {
	V        int          `json:"v"`
	ID       string       `json:"id"`
	Target   string       `json:"target"`
	IP       string       `json:"ip"`
	Method   string       `json:"method"`
	Done     bool         `json:"done"`
	Started  int64        `json:"started"`
	Finished int64        `json:"finished"`
	Error    string       `json:"error"`
	Paths    ComparePaths `json:"paths"`
}

func newComparePath() *ComparePath {
	return &ComparePath{Samples: []*int{}}
}

func newCompareResult(id string, now time.Time) *CompareResult {
	return &CompareResult{
		V:       CompareFormatVersion,
		ID:      id,
		Started: now.UnixMilli(),
		Paths:   ComparePaths{Direct: newComparePath(), VPN: newComparePath()},
	}
}

// ParseCompareRequest разбирает и проверяет запрос; id — из имени файла.
// Диапазоны port/count не ошибка: пустое — по умолчанию, count прижимается к 3..30.
func ParseCompareRequest(fileID string, data []byte) (*CompareRequest, error) {
	var req CompareRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("запрос не разобран: %v", err)
	}
	if req.V != CompareFormatVersion {
		return nil, fmt.Errorf("неподдерживаемая версия запроса: %d", req.V)
	}
	if req.ID != fileID {
		return nil, errors.New("номер в запросе не совпадает с именем файла")
	}
	target, err := normalizeCompareTarget(req.Target)
	if err != nil {
		return nil, err
	}
	req.Target = target
	switch {
	case req.Port == 0:
		req.Port = compareDefaultPort
	case req.Port < 1 || req.Port > 65535:
		return nil, fmt.Errorf("неверный порт: %d", req.Port)
	}
	switch {
	case req.Count == 0:
		req.Count = compareDefaultCount
	case req.Count < compareMinCount:
		req.Count = compareMinCount
	case req.Count > compareMaxCount:
		req.Count = compareMaxCount
	}
	return &req, nil
}

// normalizeCompareTarget: домен (в нижнем регистре, punycode), IPv4 или IPv6 без скобок.
func normalizeCompareTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", errors.New("не указана цель")
	}
	if len(target) > 255 {
		return "", errors.New("слишком длинный адрес цели")
	}
	if ip, err := netip.ParseAddr(target); err == nil {
		return ip.Unmap().String(), nil
	}
	host := strings.ToLower(strings.TrimSuffix(target, "."))
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}
	if len(host) > 253 || !compareHostRe.MatchString(host) {
		return "", fmt.Errorf("неверный адрес цели: %q", raw)
	}
	return host, nil
}

// --- файлы ---

func compareReqPath(dir, id string) string { return filepath.Join(dir, reqPrefix+id+jsonExt) }
func compareResPath(dir, id string) string { return filepath.Join(dir, resPrefix+id+jsonExt) }

// compareFileID возвращает id из имени req-<id>.json / res-<id>.json.
func compareFileID(name, prefix string) (string, bool) {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, jsonExt) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), jsonExt)
	return id, compareIDRe.MatchString(id)
}

// writeCompareResult пишет res атомарно: временный файл и переименование поверх старого.
func writeCompareResult(dir string, res *CompareResult) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	final := compareResPath(dir, res.ID)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	// Приложение может читать файл в этот момент: на Windows переименование поверх открытого
	// файла иногда не удаётся, повторяем несколько раз.
	for i := 0; ; i++ {
		err = os.Rename(tmp, final)
		if err == nil || i >= 10 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// cleanupCompareDir удаляет req/res/tmp старше часа; незавершённые res (ядро убили посреди
// замера) закрывает ошибкой, чтобы приложение не ждало вечно.
func cleanupCompareDir(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		_, isReq := compareFileID(name, reqPrefix)
		id, isRes := compareFileID(name, resPrefix)
		if !isReq && !isRes && !(strings.HasPrefix(name, resPrefix) && strings.HasSuffix(name, ".tmp")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, name)
		if now.Sub(info.ModTime()) > compareMaxAge {
			_ = os.Remove(path)
			continue
		}
		if isRes {
			closeUnfinishedResult(dir, id, path, now)
		}
	}
}

func closeUnfinishedResult(dir, id, path string, now time.Time) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var res CompareResult
	if json.Unmarshal(data, &res) != nil || res.Done {
		return
	}
	if res.Paths.Direct == nil {
		res.Paths.Direct = newComparePath()
	}
	if res.Paths.VPN == nil {
		res.Paths.VPN = newComparePath()
	}
	res.Done = true
	res.Finished = now.UnixMilli()
	res.Error = "ядро было перезапущено во время проверки"
	_ = writeCompareResult(dir, &res)
}

// --- служба ---

type CompareOptions struct {
	Dir            string
	TestURL        string // connection-test-url: оценка качества VPN при методе icmp
	VPNOutbound    string
	DirectOutbound string
	DirectDNS      string // тег DNS-сервера «напрямую»; пусто или нет такого — системный резолвер
	Now            func() time.Time
}

// Comparer — служба ядра «Сравнить пути».
type Comparer struct {
	opts   CompareOptions
	svc    *daemon.StartedService
	access sync.Mutex
	prep   *compareRun // подготовлен на стадии Initialize
	active *compareRun // запущен на Start
}

var _ adapter.LifecycleService = (*Comparer)(nil)

// NewComparer возвращает nil, если папка не задана: функция выключена.
func NewComparer(opts CompareOptions) *Comparer {
	if opts.Dir == "" {
		return nil
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Comparer{opts: opts}
}

func (c *Comparer) Bind(svc *daemon.StartedService) { c.svc = svc }

func (c *Comparer) Name() string { return "rescue-compare" }

func (c *Comparer) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		if c.svc == nil {
			return nil
		}
		inst := c.svc.Instance()
		if inst == nil || inst.Box() == nil {
			return nil
		}
		r := newCompareRun(c.opts, inst.Box().Outbound())
		r.resolve = newCoreResolver(inst.Context(), c.opts.DirectDNS)
		c.access.Lock()
		c.prep = r
		c.access.Unlock()
	case adapter.StartStateStart:
		c.access.Lock()
		r := c.prep
		c.prep = nil
		c.access.Unlock()
		if r == nil {
			return nil
		}
		if err := os.MkdirAll(r.dir, 0o755); err != nil {
			return nil // нет папки — работаем без сравнения, ядро не останавливаем
		}
		r.start()
		c.access.Lock()
		c.active = r
		c.access.Unlock()
	}
	return nil
}

func (c *Comparer) Close() error {
	c.access.Lock()
	r := c.active
	c.active, c.prep = nil, nil
	c.access.Unlock()
	if r != nil {
		r.stop()
	}
	return nil
}

// compareRun — один запуск службы.
type compareRun struct {
	dir  string
	opts CompareOptions
	now  func() time.Time

	// Подменяются в тестах.
	vpnDialer    func() N.Dialer
	directDialer func() N.Dialer
	resolve      resolveFunc
	ping         icmpFunc
	urlTest      probeFunc

	scanEvery time.Duration
	pause     time.Duration
	timeout   time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	access  sync.Mutex
	queue   []queued
	known   map[string]struct{} // id, уже принятые в очередь или обработанные
	wake    chan struct{}
	started bool
}

type queued struct {
	id      string
	modTime time.Time
}

func newCompareRun(opts CompareOptions, outbounds adapter.OutboundManager) *compareRun {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	r := newCompareRunBase(opts)
	r.vpnDialer = func() N.Dialer {
		if ob := pickVPNOutbound(outbounds, opts.VPNOutbound); ob != nil {
			return ob
		}
		return nil
	}
	r.directDialer = func() N.Dialer {
		if ob := pickDirectOutbound(outbounds, opts.DirectOutbound); ob != nil {
			return ob
		}
		return nil
	}
	return r
}

func newCompareRunBase(opts CompareOptions) *compareRun {
	return &compareRun{
		dir:       opts.Dir,
		opts:      opts,
		now:       opts.Now,
		resolve:   systemResolve,
		ping:      systemPing,
		urlTest:   urlTestProbe,
		scanEvery: compareScanInterval,
		pause:     comparePause,
		timeout:   compareMeasureTO,
		known:     make(map[string]struct{}),
		wake:      make(chan struct{}, 1),
	}
}

func (r *compareRun) start() {
	r.ctx, r.cancel = context.WithCancel(context.Background())
	cleanupCompareDir(r.dir, r.now())
	r.started = true
	r.wg.Add(2)
	go r.scanLoop()
	go r.workLoop()
}

func (r *compareRun) stop() {
	if !r.started {
		return
	}
	r.cancel()
	r.wg.Wait()
	// Ожидающим запросам сообщаем, что ядро остановлено.
	r.access.Lock()
	rest := r.queue
	r.queue = nil
	r.access.Unlock()
	for _, q := range rest {
		r.writeError(q.id, "ядро остановлено")
	}
}

func (r *compareRun) scanLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.scanEvery)
	defer ticker.Stop()
	for {
		r.scan()
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// scan берёт новые req-*.json без res: в очередь (до 30) или сразу с ошибкой.
func (r *compareRun) scan() {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	present := make(map[string]struct{})
	hasRes := make(map[string]struct{})
	var fresh []queued
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if id, ok := compareFileID(e.Name(), resPrefix); ok {
			hasRes[id] = struct{}{}
			present[id] = struct{}{}
			continue
		}
		id, ok := compareFileID(e.Name(), reqPrefix)
		if !ok {
			continue
		}
		present[id] = struct{}{}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fresh = append(fresh, queued{id: id, modTime: info.ModTime()})
	}
	sort.Slice(fresh, func(i, j int) bool {
		if !fresh[i].modTime.Equal(fresh[j].modTime) {
			return fresh[i].modTime.Before(fresh[j].modTime)
		}
		return fresh[i].id < fresh[j].id
	})

	r.access.Lock()
	// Забываем то, что приложение уже удалило.
	for id := range r.known {
		if _, ok := present[id]; !ok {
			delete(r.known, id)
		}
	}
	var overflow []string
	added := false
	for _, q := range fresh {
		if _, ok := r.known[q.id]; ok {
			continue
		}
		if _, ok := hasRes[q.id]; ok {
			r.known[q.id] = struct{}{}
			continue
		}
		r.known[q.id] = struct{}{}
		if len(r.queue) >= compareMaxQueue {
			overflow = append(overflow, q.id)
			continue
		}
		r.queue = append(r.queue, q)
		added = true
	}
	r.access.Unlock()

	for _, id := range overflow {
		r.writeError(id, "слишком много запросов")
	}
	if added {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

func (r *compareRun) workLoop() {
	defer r.wg.Done()
	for {
		r.access.Lock()
		var next *queued
		if len(r.queue) > 0 {
			q := r.queue[0]
			r.queue = r.queue[1:]
			next = &q
		}
		r.access.Unlock()
		if next == nil {
			select {
			case <-r.ctx.Done():
				return
			case <-r.wake:
			}
			continue
		}
		if r.ctx.Err() != nil {
			r.writeError(next.id, "ядро остановлено")
			return
		}
		r.process(next.id)
	}
}

// process — один запрос целиком: прочитать, проверить, измерить.
func (r *compareRun) process(id string) {
	data, err := os.ReadFile(compareReqPath(r.dir, id))
	if err != nil {
		if os.IsNotExist(err) {
			return // приложение уже забрало запрос обратно
		}
		r.writeError(id, "запрос не прочитан: "+err.Error())
		return
	}
	req, err := ParseCompareRequest(id, data)
	if err != nil {
		r.writeError(id, err.Error())
		return
	}
	newCompareMeasure(r, req).run()
}

func (r *compareRun) writeError(id, text string) {
	res := newCompareResult(id, r.now())
	res.Done = true
	res.Finished = res.Started
	res.Error = text
	_ = writeCompareResult(r.dir, res)
}

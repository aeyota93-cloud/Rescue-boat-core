package rescuestats

// Запись файлов статистики: JSON Lines, одна запись — одна строка, только дописывание.
// Файлы по местной дате: errors-YYYYMMDD.jsonl, quality-YYYYMMDD.jsonl.
// Старые файлы удаляются (errors — 7 дней, quality — 30), ошибок не больше 5000 строк в сутки,
// сверх — одна строка suppressed при смене суток или остановке.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	FormatVersion     = 1
	ErrorsKeepDays    = 7
	QualityKeepDays   = 30
	MaxErrorsPerDay   = 5000
	CollapseWindow    = time.Second
	errorsFilePrefix  = "errors-"
	qualityFilePrefix = "quality-"
	fileSuffix        = ".jsonl"
	dateLayout        = "20060102"
)

// ErrorRecord — строка errors-*.jsonl. Порядок полей — как в договоре.
type ErrorRecord struct {
	V     int    `json:"v"`
	T     int64  `json:"t"`
	Kind  string `json:"kind"`
	App   string `json:"app"`
	Host  string `json:"host"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Net   string `json:"net"`
	Route string `json:"route"`
	DurMs int64  `json:"dur_ms"`
	GapMs int64  `json:"gap_ms,omitempty"`
	N     int    `json:"n"`
	Msg   string `json:"msg"`
}

type suppressedRecord struct {
	V    int    `json:"v"`
	T    int64  `json:"t"`
	Kind string `json:"kind"`
	N    int    `json:"n"`
}

// ProbeRecord — замер задержки, samples: мс или null (потеря).
type ProbeRecord struct {
	V       int    `json:"v"`
	T       int64  `json:"t"`
	Type    string `json:"type"`
	Path    string `json:"path"`
	Samples []*int `json:"samples"`
}

// CountersRecord — счётчики за прошедшую минуту.
type CountersRecord struct {
	V       int    `json:"v"`
	T       int64  `json:"t"`
	Type    string `json:"type"`
	Conns   int64  `json:"conns"`
	Errs    int64  `json:"errs"`
	DNSOk   int64  `json:"dns_ok"`
	DNSFail int64  `json:"dns_fail"`
}

type collapseKey struct {
	kind, app, host, route string
}

type pendingError struct {
	rec   ErrorRecord
	first time.Time
}

// Store пишет файлы; безопасен для вызова из разных горутин.
type Store struct {
	dir string
	now func() time.Time

	access     sync.Mutex
	closed     bool
	pending    map[collapseKey]*pendingError
	day        string // местная дата, к которой относятся счётчики ниже
	dayLines   int    // строк ошибок, записанных за day
	suppressed int    // пропущено событий за day
	lastSupp   time.Time
	lastClean  string
}

func NewStore(dir string, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{dir: dir, now: now, pending: make(map[collapseKey]*pendingError)}
}

// Open создаёт папку, чистит старые файлы и узнаёт, сколько ошибок уже записано сегодня.
func (s *Store) Open() error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	s.access.Lock()
	defer s.access.Unlock()
	now := s.now()
	s.cleanupLocked(now)
	s.day = dayOf(now)
	s.dayLines = countLines(s.errorsPath(s.day))
	return nil
}

// AddError принимает событие; одинаковые kind+app+host+route в пределах 1 с схлопываются.
func (s *Store) AddError(rec ErrorRecord) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return
	}
	rec.V = FormatVersion
	if rec.N <= 0 {
		rec.N = 1
	}
	at := time.UnixMilli(rec.T)
	key := collapseKey{rec.Kind, rec.App, rec.Host, rec.Route}
	if p, ok := s.pending[key]; ok {
		if at.Sub(p.first) < CollapseWindow && dayOf(at) == dayOf(p.first) {
			p.rec.N += rec.N
			return
		}
		delete(s.pending, key)
		s.writeErrorLocked(p.rec)
	}
	s.pending[key] = &pendingError{rec: rec, first: at}
}

// Flush пишет схлопнутые события, окно которых закончилось (all — все сразу).
func (s *Store) Flush(all bool) {
	s.access.Lock()
	defer s.access.Unlock()
	s.flushLocked(all)
}

func (s *Store) flushLocked(all bool) {
	now := s.now()
	var ready []*pendingError
	for key, p := range s.pending {
		if all || now.Sub(p.first) >= CollapseWindow {
			ready = append(ready, p)
			delete(s.pending, key)
		}
	}
	// По времени, чтобы строки в файле шли по порядку.
	for i := 1; i < len(ready); i++ {
		for j := i; j > 0 && ready[j].rec.T < ready[j-1].rec.T; j-- {
			ready[j], ready[j-1] = ready[j-1], ready[j]
		}
	}
	for _, p := range ready {
		s.writeErrorLocked(p.rec)
	}
	s.rollDayLocked(dayOf(now))
}

func (s *Store) writeErrorLocked(rec ErrorRecord) {
	at := time.UnixMilli(rec.T)
	day := dayOf(at)
	if day != s.day {
		if day < s.day {
			// Запоздавшее событие прошлых суток: пишем в свой файл без учёта лимита.
			appendLine(s.errorsPath(day), rec)
			return
		}
		s.rollDayLocked(day)
	}
	if s.dayLines >= MaxErrorsPerDay {
		s.suppressed += rec.N
		s.lastSupp = at
		return
	}
	if appendLine(s.errorsPath(day), rec) == nil {
		s.dayLines++
	}
}

// rollDayLocked: при смене суток — строка suppressed за прошлые сутки, сброс лимита, чистка.
func (s *Store) rollDayLocked(day string) {
	if day <= s.day {
		return
	}
	s.writeSuppressedLocked()
	s.day = day
	s.dayLines = countLines(s.errorsPath(day))
	s.cleanupLocked(s.now())
}

func (s *Store) writeSuppressedLocked() {
	if s.suppressed == 0 {
		return
	}
	_ = appendLine(s.errorsPath(s.day), suppressedRecord{
		V:    FormatVersion,
		T:    s.lastSupp.UnixMilli(),
		Kind: KindSuppressed,
		N:    s.suppressed,
	})
	s.suppressed = 0
}

// AddQuality пишет строку probe/counters сразу.
func (s *Store) AddQuality(rec any, at time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return
	}
	_ = appendLine(s.qualityPath(dayOf(at)), rec)
}

// Close дописывает схлопнутые события и строку suppressed.
func (s *Store) Close() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return
	}
	s.flushLocked(true)
	s.writeSuppressedLocked()
	s.closed = true
}

// Cleanup — удаление старых файлов (раз в сутки; повторный вызов в те же сутки ничего не делает).
func (s *Store) Cleanup() {
	s.access.Lock()
	defer s.access.Unlock()
	s.cleanupLocked(s.now())
}

func (s *Store) cleanupLocked(now time.Time) {
	today := dayOf(now)
	if s.lastClean == today {
		return
	}
	s.lastClean = today
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	errorsBorder := dayOf(midnight.AddDate(0, 0, -ErrorsKeepDays))
	qualityBorder := dayOf(midnight.AddDate(0, 0, -QualityKeepDays))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, fileSuffix) {
			continue
		}
		var date, border string
		switch {
		case strings.HasPrefix(name, errorsFilePrefix):
			date, border = strings.TrimSuffix(strings.TrimPrefix(name, errorsFilePrefix), fileSuffix), errorsBorder
		case strings.HasPrefix(name, qualityFilePrefix):
			date, border = strings.TrimSuffix(strings.TrimPrefix(name, qualityFilePrefix), fileSuffix), qualityBorder
		default:
			continue
		}
		if _, err := time.Parse(dateLayout, date); err != nil {
			continue
		}
		if date < border {
			_ = os.Remove(filepath.Join(s.dir, name))
		}
	}
}

func (s *Store) errorsPath(day string) string {
	return filepath.Join(s.dir, errorsFilePrefix+day+fileSuffix)
}

func (s *Store) qualityPath(day string) string {
	return filepath.Join(s.dir, qualityFilePrefix+day+fileSuffix)
}

func dayOf(t time.Time) string {
	return t.Local().Format(dateLayout)
}

// appendLine дописывает запись одной строкой за один вызов Write.
func appendLine(path string, rec any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(buf.Bytes())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// countLines — сколько записей ошибок уже в файле (suppressed не в счёт).
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 || bytes.Contains(line, []byte(`"kind":"suppressed"`)) {
			continue
		}
		n++
	}
	return n
}

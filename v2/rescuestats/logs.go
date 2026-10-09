package rescuestats

// Журнал ядра как источник причин. sing-box отдаёт все строки (любого уровня) в журнал
// службы (daemon.StartedService), подписка — тем же путём, что у приложения (SubscribeLog),
// только без gRPC. Строки соединений помечены номером из контекста: «[номер длительность]».
// Отсюда берутся:
//   - ERROR по известному соединению — ошибка уже установленного соединения
//     («connection download closed: read: connection reset by peer» и т. п.);
//   - dns: exchange / lookup domain — запросы DNS (счётчик dns_ok);
//   - dns: exchange … failed for … / lookup failed for … — неудачные (dns_fail),
//     у exchange (DNS-запрос программы) ещё и строка ошибки kind=dns.

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"google.golang.org/grpc/metadata"
)

var (
	// «ERROR[0012] [3456 50ms] connection: …» (после снятия цветов).
	logLineRe   = regexp.MustCompile(`^\S*?\[\d+\]\s+(?:\[(\d+)\s[^\]]*\]\s+)?(.*)$`)
	logBareIDRe = regexp.MustCompile(`^\[(\d+)\s[^\]]*\]\s+(.*)$`)
	dnsFailRe   = regexp.MustCompile(`^exchange (\S+) failed for (\S+)`)
)

// parseLogLine разбирает строку журнала: номер соединения (если есть) и текст «тег: сообщение».
func parseLogLine(message string) (id uint32, hasID bool, text string) {
	message = strings.TrimSpace(ansiRe.ReplaceAllString(message, ""))
	var idStr string
	if m := logLineRe.FindStringSubmatch(message); m != nil {
		idStr, text = m[1], m[2]
	} else if m := logBareIDRe.FindStringSubmatch(message); m != nil {
		idStr, text = m[1], m[2]
	} else {
		return 0, false, message
	}
	if idStr != "" {
		if v, err := strconv.ParseUint(idStr, 10, 32); err == nil {
			return uint32(v), true, text
		}
	}
	return 0, false, text
}

// splitTag: «connection: open …» → «connection», «open …».
func splitTag(text string) (tag, msg string) {
	if i := strings.Index(text, ": "); i > 0 && !strings.Contains(text[:i], " ") {
		return text[:i], text[i+2:]
	}
	return "", text
}

// handleLog — одна строка журнала.
func (r *run) handleLog(level log.Level, message string) {
	id, hasID, text := parseLogLine(message)
	if !hasID {
		return // фоновые строки ядра (обновления, свои проверки) — не программы
	}
	if r.isOwnID(id) {
		return // собственные замеры
	}
	tag, msg := splitTag(text)
	if tag == "dns" {
		r.handleDNSLog(level, msg)
		return
	}
	if level > log.LevelError {
		return
	}
	if info := r.lookupID(id); info != nil {
		r.connError(info, msg, nil)
	}
}

func (r *run) handleDNSLog(level log.Level, msg string) {
	switch {
	case strings.HasPrefix(msg, "exchange ") && strings.Contains(msg, " failed for "):
		r.dnsFail.Add(1)
		m := dnsFailRe.FindStringSubmatch(msg)
		if m == nil {
			return
		}
		route := RouteVPN
		if t := strings.ToLower(m[1]); strings.Contains(t, "direct") || strings.Contains(t, "local") {
			route = RouteDirect
		}
		r.store.AddError(ErrorRecord{
			T:     r.now().UnixMilli(),
			Kind:  KindDNS,
			Host:  strings.TrimSuffix(m[2], "."),
			Net:   "udp",
			Route: route,
			Msg:   CleanMsg(msg),
		})
	case strings.HasPrefix(msg, "lookup failed for "):
		r.dnsFail.Add(1)
	case strings.HasPrefix(msg, "exchange "), strings.HasPrefix(msg, "lookup domain "):
		r.dnsStart.Add(1)
	}
}

// logStream — поток SubscribeLog без gRPC: строки сразу уходят в handleLog.
type logStream struct {
	ctx context.Context
	run *run
	// Первая порция — строки, накопленные до подписки; они уже не про текущие соединения.
	skipFirst bool
}

func (s *logStream) Send(l *daemon.Log) error {
	if !s.skipFirst {
		s.skipFirst = true
		if l.Reset_ {
			return nil
		}
	}
	for _, m := range l.Messages {
		s.run.handleLog(log.Level(m.Level), m.Message)
	}
	return nil
}

func (s *logStream) SetHeader(metadata.MD) error  { return nil }
func (s *logStream) SendHeader(metadata.MD) error { return nil }
func (s *logStream) SetTrailer(metadata.MD)       {}
func (s *logStream) Context() context.Context     { return s.ctx }
func (s *logStream) SendMsg(any) error            { return nil }
func (s *logStream) RecvMsg(any) error            { return nil }

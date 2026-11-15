package rescuestats

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

func TestAudit_C2_09_DNSFailureAcrossCounterIntervals(t *testing.T) {
	e := newTestEnv(t)
	e.clock.Set(baseTime().Truncate(time.Minute).Add(time.Minute - time.Millisecond))
	r := e.run
	started := e.clock.Now()
	f := log.Formatter{BaseTime: started, DisableLineBreak: true}
	emit := func(level log.Level, msg string) {
		r.handleLog(level, f.Format(ctxWithID(209, started), level, "dns", msg, e.clock.Now()))
	}
	emit(log.LevelDebug, "exchange example.test. IN A")
	first := r.takeCounters(e.clock.Now())
	e.clock.Add(2 * time.Millisecond)
	emit(log.LevelError, "exchange dns-remote failed for example.test. IN A: timeout")
	second := r.takeCounters(e.clock.Now())
	if ok, fail := first.DNSOk+second.DNSOk, first.DNSFail+second.DNSFail; ok != 0 || fail != 1 {
		t.Errorf("C2-09: ожидали DNSOk=0 и DNSFail=1 для одного неудачного запроса на границе интервалов, получены DNSOk=%d и DNSFail=%d", ok, fail)
	}
	if empty := r.takeCounters(e.clock.Now()); empty.DNSOk != 0 || empty.DNSFail != 0 {
		t.Fatalf("C2-09: ожидали пустой следующий интервал, получены DNSOk=%d и DNSFail=%d", empty.DNSOk, empty.DNSFail)
	}
	// Успешный lookup должен считаться в интервале завершения ровно один раз.
	successCtx := ctxWithID(210, e.clock.Now())
	r.handleLog(log.LevelDebug, f.Format(successCtx, log.LevelDebug, "dns", "lookup domain success.example.test", e.clock.Now()))
	beforeSuccess := r.takeCounters(e.clock.Now())
	e.clock.Add(time.Minute)
	r.handleLog(log.LevelInfo, f.Format(successCtx, log.LevelInfo, "dns", "lookup succeed for success.example.test: 192.0.2.1", e.clock.Now()))
	afterSuccess := r.takeCounters(e.clock.Now())
	if beforeSuccess.DNSOk != 0 || afterSuccess.DNSOk != 1 || beforeSuccess.DNSFail+afterSuccess.DNSFail != 0 {
		t.Fatalf("C2-09: ожидали один успех после завершения lookup и ни одной ошибки, получены DNSOk до/после=%d/%d и DNSFail=%d", beforeSuccess.DNSOk, afterSuccess.DNSOk, beforeSuccess.DNSFail+afterSuccess.DNSFail)
	}
}

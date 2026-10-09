package rescuestats

// «Замирание» UDP: соединение получало данные, затем ≥1500 мс не получало ничего,
// хотя программа продолжала отправлять. Счётчики опрашиваются раз в 250 мс.

import "time"

const (
	StallThreshold = 1500 * time.Millisecond
	StallPoll      = 250 * time.Millisecond
)

// stallDetector — состояние одного UDP-соединения. Не потокобезопасен: зовётся из одной горутины.
type stallDetector struct {
	started  bool
	lastUp   int64
	lastDown int64
	// lastRecv — когда в последний раз пришли данные; 0 — ещё не приходили.
	lastRecv time.Time
	// lastSend — когда в последний раз программа отправила что-то после lastRecv.
	lastSend time.Time
}

// Observe принимает текущие счётчики (отправлено, получено) и возвращает длину
// закончившегося «замирания», если оно было (данные снова пошли).
func (d *stallDetector) Observe(now time.Time, up, down int64) (time.Duration, bool) {
	if !d.started {
		d.started = true
		d.lastUp, d.lastDown = up, down
		if down > 0 {
			d.lastRecv = now
		}
		return 0, false
	}
	var gap time.Duration
	var stalled bool
	if down > d.lastDown {
		// Отправка в тот же опрос, что и ответ, не в счёт: программа могла молчать всю паузу.
		if !d.lastRecv.IsZero() && d.sentDuringGap() {
			gap = now.Sub(d.lastRecv)
			stalled = true
		}
		d.lastRecv = now
		d.lastSend = time.Time{}
	} else if up > d.lastUp && !d.lastRecv.IsZero() {
		d.lastSend = now
	}
	d.lastUp, d.lastDown = up, down
	return gap, stalled
}

// Finish — соединение закрылось (или сбор остановлен): незакончившееся «замирание»
// считается до последней отправки программы.
func (d *stallDetector) Finish() (time.Duration, bool) {
	if d.lastRecv.IsZero() || !d.sentDuringGap() {
		return 0, false
	}
	gap := d.lastSend.Sub(d.lastRecv)
	d.lastSend = time.Time{}
	return gap, true
}

// Программа продолжала отправлять, когда пауза уже длилась ≥ порога.
func (d *stallDetector) sentDuringGap() bool {
	return !d.lastSend.IsZero() && d.lastSend.Sub(d.lastRecv) >= StallThreshold
}

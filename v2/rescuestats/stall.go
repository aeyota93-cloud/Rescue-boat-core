package rescuestats

// «Замирание» UDP: в ПЛОТНОМ потоке (игровой матч: десятки пакетов в секунду в обе стороны)
// данные перестали приходить на ≥1500 мс, хотя программа продолжала отправлять.
// Счётчики опрашиваются раз в 250 мс.
//
// Редкие служебные соединения (опрос регионов, keep-alive: пакет раз в 1–30 с) замираниями
// не считаются: сервер просто перестал отвечать, а программа изредка шлёт. Для этого
// пауза засчитывается, только если перед ней поток был плотным.

import (
	"math/bits"
	"time"
)

const (
	StallThreshold = 1500 * time.Millisecond
	StallPoll      = 250 * time.Millisecond

	// StallMaxGap — верхняя граница паузы: дольше этого — не замирание, а конец сессии
	// (игра закрыла сокет, сервер ушёл), в статистику не пишем.
	StallMaxGap = 60 * time.Second

	// Плотность потока: в скольких из последних stallDensityWindow опросов (8 × 250 мс = 2 с)
	// приходили данные. Замирание засчитывается, только если в момент последнего приёма
	// перед паузой было ≥ stallDensityMin таких опросов. Матч (десятки пакетов/с) даёт 8 из 8;
	// keep-alive раз в 1 с и реже — не больше 2 из 8; опрос регионов (несколько ответов
	// подряд) — 3–4 из 8. Порог 5 отсекает всё это с запасом.
	stallDensityWindow = 8
	stallDensityMin    = 5
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
	// history — по биту на каждый из последних опросов (младший бит — самый свежий):
	// 1 — в этом опросе пришли данные.
	history uint8
	// recvDensity — плотность потока (число единиц в history) в момент последнего приёма.
	recvDensity int
}

// Observe принимает текущие счётчики (отправлено, получено) и возвращает длину
// закончившегося «замирания», если оно было (данные снова пошли).
func (d *stallDetector) Observe(now time.Time, up, down int64) (time.Duration, bool) {
	if !d.started {
		d.started = true
		d.lastUp, d.lastDown = up, down
		if down > 0 {
			d.lastRecv = now
			d.history = 1
			d.recvDensity = 1
		}
		return 0, false
	}
	var gap time.Duration
	var stalled bool
	d.history <<= 1
	if down > d.lastDown {
		d.history |= 1
		// Отправка в тот же опрос, что и ответ, не в счёт: программа могла молчать всю паузу.
		if !d.lastRecv.IsZero() && d.sentDuringGap() {
			if g := now.Sub(d.lastRecv); g <= StallMaxGap {
				gap = g
				stalled = true
			}
		}
		d.lastRecv = now
		d.recvDensity = bits.OnesCount8(d.history)
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
	if gap > StallMaxGap {
		return 0, false
	}
	return gap, true
}

// Пауза могла быть замиранием: поток перед ней был плотным, и программа продолжала
// отправлять, когда пауза уже длилась ≥ порога.
func (d *stallDetector) sentDuringGap() bool {
	return d.recvDensity >= stallDensityMin &&
		!d.lastSend.IsZero() && d.lastSend.Sub(d.lastRecv) >= StallThreshold
}

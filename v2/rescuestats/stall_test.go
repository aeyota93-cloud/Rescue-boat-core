package rescuestats

import (
	"testing"
	"time"
)

// feed прогоняет опросы раз в 250 мс: up/down — накопленные счётчики на каждом шаге.
func feed(d *stallDetector, start time.Time, up, down []int64) (gaps []time.Duration) {
	for i := range up {
		if gap, ok := d.Observe(start.Add(time.Duration(i)*StallPoll), up[i], down[i]); ok {
			gaps = append(gaps, gap)
		}
	}
	return gaps
}

func TestStallDetected(t *testing.T) {
	var d stallDetector
	start := baseTime()
	// 0..7: плотный поток (данные в каждый опрос); 8..15 (2 с): программа шлёт, ответа нет;
	// 16: ответ снова пошёл. На редком потоке (2 опроса с данными) это не замирание — см. ниже.
	var up, down []int64
	for i := int64(1); i <= 8; i++ {
		up, down = append(up, i*10), append(down, i*10)
	}
	for i := int64(1); i <= 8; i++ {
		up, down = append(up, 80+i*10), append(down, 80)
	}
	up, down = append(up, 180), append(down, 90)
	gaps := feed(&d, start, up, down)
	if len(gaps) != 1 || gaps[0] != 2250*time.Millisecond {
		t.Fatalf("want one stall of 2250ms, got %v", gaps)
	}
	if _, ok := d.Finish(); ok {
		t.Error("finished stall must not be reported twice")
	}
}

func TestStallShortPauseIgnored(t *testing.T) {
	var d stallDetector
	// пауза 1250 мс — меньше порога
	up := []int64{10, 20, 30, 40, 50, 60, 70}
	down := []int64{10, 20, 20, 20, 20, 20, 30}
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("short pause reported: %v", gaps)
	}
}

func TestStallProgramSilentIgnored(t *testing.T) {
	var d stallDetector
	// программа тоже молчит — это не «замирание», а тишина
	up := []int64{10, 20, 20, 20, 20, 20, 20, 20, 20, 20, 30}
	down := []int64{10, 20, 20, 20, 20, 20, 20, 20, 20, 20, 30}
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("silence reported as stall: %v", gaps)
	}
	if _, ok := d.Finish(); ok {
		t.Error("silence reported on finish")
	}
}

func TestStallNeverReceivedIgnored(t *testing.T) {
	var d stallDetector
	// данных не было ни разу — это не «замирание» (сервер просто не отвечает)
	up := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	down := make([]int64, len(up))
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("reported without prior data: %v", gaps)
	}
	if _, ok := d.Finish(); ok {
		t.Error("reported on finish without prior data")
	}
}

func TestStallUnfinishedReportedOnClose(t *testing.T) {
	var d stallDetector
	// плотно получали, потом 3 с только отправка, затем соединение закрылось
	var up, down []int64
	for i := int64(1); i <= 8; i++ {
		up, down = append(up, i*10), append(down, i*10)
	}
	for i := int64(1); i <= 12; i++ {
		up, down = append(up, 80+i*10), append(down, 80)
	}
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("unfinished stall reported early: %v", gaps)
	}
	gap, ok := d.Finish()
	if !ok || gap != 3*time.Second {
		t.Fatalf("want stall 3s on finish, got %v %v", gap, ok)
	}
}

// scenario собирает счётчики по опросам из функции: recv(i)/send(i) — число пакетов
// в опросе i (номер от 0). Возвращает накопленные up/down.
func scenario(polls int, send, recv func(i int) int64) (up, down []int64) {
	var u, dn int64
	for i := 0; i < polls; i++ {
		u += send(i)
		dn += recv(i)
		up, down = append(up, u), append(down, dn)
	}
	return up, down
}

// (а) Плотный поток 40 пакетов/с (10 за опрос) в обе стороны, пауза 3 с при
// продолжающейся отправке, затем данные вернулись — замирание 3 с.
func TestStallDenseStreamPause(t *testing.T) {
	var d stallDetector
	const dense, pause = 40, 12 // 40 опросов (10 с) потока, 12 опросов (3 с) паузы
	up, down := scenario(dense+pause+4,
		func(i int) int64 { return 10 },
		func(i int) int64 {
			if i < dense || i >= dense+pause {
				return 10
			}
			return 0
		})
	gaps := feed(&d, baseTime(), up, down)
	if len(gaps) != 1 || gaps[0] != 3250*time.Millisecond {
		t.Fatalf("want one stall of 3250ms (3 с пауза + опрос возобновления), got %v", gaps)
	}
}

// (б) Keep-alive раз в 5 с с ответами, затем сервер замолчал, программа шлёт раз в 5 с
// ещё 2 минуты, соединение закрылось: редкий поток — не замирание.
func TestStallKeepAliveIgnored(t *testing.T) {
	var d stallDetector
	every5s := func(i int) bool { return i%20 == 0 }
	const alive = 20 * 12 // 1 минута keep-alive с ответами
	up, down := scenario(alive+20*24,
		func(i int) int64 {
			if every5s(i) {
				return 1
			}
			return 0
		},
		func(i int) int64 {
			if i < alive && every5s(i) {
				return 1
			}
			return 0
		})
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("keep-alive reported as stall: %v", gaps)
	}
	if gap, ok := d.Finish(); ok {
		t.Fatalf("keep-alive reported on finish: %v", gap)
	}
}

// (в) Плотный поток, затем пауза 90 с при продолжающейся отправке: дольше StallMaxGap —
// это конец сессии, не замирание. И при возобновлении, и при закрытии.
func TestStallTooLongIgnored(t *testing.T) {
	const dense, pause = 40, 90 * 4
	send := func(i int) int64 { return 10 }
	for _, resumed := range []bool{true, false} {
		var d stallDetector
		tail := 4
		if !resumed {
			tail = 0
		}
		up, down := scenario(dense+pause+tail, send, func(i int) int64 {
			if i < dense || i >= dense+pause {
				return 10
			}
			return 0
		})
		if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
			t.Fatalf("resumed=%v: 90s pause reported: %v", resumed, gaps)
		}
		if gap, ok := d.Finish(); ok {
			t.Fatalf("resumed=%v: 90s pause reported on finish: %v", resumed, gap)
		}
	}
}

// (г) Опрос регионов: 3 ответа подряд, затем тишина и редкая отправка — не замирание.
func TestStallRegionPollIgnored(t *testing.T) {
	var d stallDetector
	up, down := scenario(80,
		func(i int) int64 {
			if i < 3 || i%8 == 0 { // 3 запроса, потом раз в 2 с
				return 1
			}
			return 0
		},
		func(i int) int64 {
			if i < 3 {
				return 1
			}
			return 0
		})
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("region poll reported as stall: %v", gaps)
	}
	if gap, ok := d.Finish(); ok {
		t.Fatalf("region poll reported on finish: %v", gap)
	}
}

// Граница плотности: 4 из 8 опросов — ещё мало, 5 из 8 — уже поток.
func TestStallDensityBoundary(t *testing.T) {
	for _, tc := range []struct {
		recvPolls int
		want      bool
	}{{4, false}, {5, true}} {
		var d stallDetector
		// recvPolls ответов подряд в начале, потом 8 опросов (2 с) паузы с отправкой, затем возобновление
		up, down := scenario(tc.recvPolls+8+1,
			func(i int) int64 { return 1 },
			func(i int) int64 {
				if i < tc.recvPolls || i == tc.recvPolls+8 {
					return 1
				}
				return 0
			})
		gaps := feed(&d, baseTime(), up, down)
		if (len(gaps) == 1) != tc.want {
			t.Errorf("recvPolls=%d: want stall=%v, got %v", tc.recvPolls, tc.want, gaps)
		}
	}
}

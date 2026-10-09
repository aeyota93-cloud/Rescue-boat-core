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
	// 0..1: данные идут; 2..9 (2 с): программа шлёт, ответа нет; 10: ответ снова пошёл.
	up := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110}
	down := []int64{10, 20, 20, 20, 20, 20, 20, 20, 20, 20, 30}
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
	// получали, потом 3 с только отправка, затем соединение закрылось
	up := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140}
	down := []int64{10, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20}
	if gaps := feed(&d, baseTime(), up, down); len(gaps) != 0 {
		t.Fatalf("unfinished stall reported early: %v", gaps)
	}
	gap, ok := d.Finish()
	if !ok || gap != 3*time.Second {
		t.Fatalf("want stall 3s on finish, got %v %v", gap, ok)
	}
}

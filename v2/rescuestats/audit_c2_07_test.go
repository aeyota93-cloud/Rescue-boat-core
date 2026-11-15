package rescuestats

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

func TestAudit_C2_07_RetriesFinalPublishWithoutRemeasure(t *testing.T) {
	dir := t.TempDir()
	r := newCompareRunBase(CompareOptions{Dir: dir, Now: time.Now})
	r.directDialer = func() N.Dialer { return nil }
	r.vpnDialer = func() N.Dialer { return nil }
	r.ctx, r.cancel = context.WithCancel(context.Background())
	defer r.cancel()
	req := &CompareRequest{V: CompareFormatVersion, ID: "auditc207", Target: "192.0.2.1", Port: 443, Count: 3}
	m := newCompareMeasure(r, req)
	if err := writeCompareResult(dir, m.res); err != nil {
		t.Fatalf("C2-07: ожидали начальный результат, запись вернула %v", err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("C2-07: ожидали JSON запроса, получена ошибка %v", err)
	}
	if err := os.WriteFile(compareReqPath(dir, req.ID), data, 0o600); err != nil {
		t.Fatalf("C2-07: ожидали файл запроса, запись вернула %v", err)
	}
	r.known[req.ID] = struct{}{}
	tmp := compareResPath(dir, req.ID) + ".tmp"
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatalf("C2-07: ожидали временную преграду записи, Mkdir вернул %v", err)
	}
	m.finish("")
	read := func() CompareResult {
		t.Helper()
		data, err := os.ReadFile(compareResPath(dir, req.ID))
		if err != nil {
			t.Fatalf("C2-07: ожидали сохранённый результат, чтение вернуло %v", err)
		}
		var got CompareResult
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("C2-07: ожидали JSON результата, разбор вернул %v", err)
		}
		return got
	}
	if got := read(); got.Done {
		t.Fatal("C2-07: ожидали отказ финальной записи при каталоге вместо tmp, результат уже done:true")
	}
	if err := os.Remove(tmp); err != nil {
		t.Fatalf("C2-07: ожидали устранение временного отказа, Remove вернул %v", err)
	}
	// Используем штатный scan, не вызываем finish/publish повторно из теста.
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		r.scan()
		r.access.Lock()
		queued := len(r.queue)
		r.access.Unlock()
		if queued != 0 {
			t.Fatalf("C2-07: ожидали повтор только сохранения, в очередь измерений добавлено %d запросов", queued)
		}
		if got := read(); got.Done {
			if got.Finished != m.res.Finished || got.Error != "" {
				t.Fatalf("C2-07: ожидали исходный успешный финал, получены finished=%d и error=%q", got.Finished, got.Error)
			}
			return
		}
		select {
		case <-poll.C:
		case <-limit.C:
			t.Fatal("C2-07: ожидали done:true после устранения отказа без повторного измерения, через 2 с на диске осталось done:false")
		}
	}
}

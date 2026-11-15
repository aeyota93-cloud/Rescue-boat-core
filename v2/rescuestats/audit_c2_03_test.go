package rescuestats

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// AddQuality принимает any: блокируем штатный appendLine на сериализации под
// Store.access. Файловое I/O выполняется под тем же замком; скорость диска не измеряем.
type auditC203Record struct {
	entered chan struct{}
	release chan struct{}
}

func (r auditC203Record) MarshalJSON() ([]byte, error) {
	close(r.entered)
	select {
	case <-r.release:
		return []byte(`{"type":"counters"}`), nil
	case <-time.After(3 * time.Second):
		return nil, errors.New("C2-03: запись не освобождена за 3 с")
	}
}

func TestAudit_C2_03_SlowStoreDoesNotBlockConnections(t *testing.T) {
	e := newTestEnv(t)
	r := e.run
	info := r.register(context.Background(), chromeMetadata(), "udp", e.selectG)
	closing := r.register(context.Background(), chromeMetadata(), "tcp", e.selectG)
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	tracked := newTrackedConn(client, closing, r)
	step := func(up, down int64) {
		info.up.Store(up)
		info.down.Store(down)
		r.maintain()
		e.clock.Add(StallPoll)
	}
	for i := int64(1); i <= 8; i++ {
		step(i*100, i*100)
	}
	for i := int64(0); i < 8; i++ {
		step(900+i*100, 800)
	}
	// Следующий maintain обнаружит окончание настоящего замирания UDP.
	info.up.Store(1700)
	info.down.Store(900)
	rec := auditC203Record{entered: make(chan struct{}), release: make(chan struct{})}
	var wg sync.WaitGroup
	defer func() {
		close(rec.release)
		joined := make(chan struct{})
		go func() { wg.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(500 * time.Millisecond):
			t.Error("C2-03: ожидали завершение операций после освобождения записи, они не завершились")
		}
	}()
	launch := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	launch(func() { r.store.AddQuality(rec, e.clock.Now()) })
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	select {
	case <-rec.entered:
	case <-limit.C:
		t.Fatal("C2-03: ожидали вход AddQuality в запись, запись не началась за 2 с")
	}
	maintained := make(chan struct{})
	launch(func() { r.maintain(); close(maintained) })
	// Не даём регистрации проскочить до maintain: ждём удержания run.access
	// либо завершения maintain, если исправленный код уже освободил замок.
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
barrier:
	for {
		if !r.access.TryLock() {
			break
		}
		r.access.Unlock()
		select {
		case <-maintained:
			break barrier
		case <-poll.C:
		case <-limit.C:
			t.Fatal("C2-03: ожидали вход maintain в обработку UDP, барьер не достигнут за 2 с")
		}
	}
	finished := make(chan string, 3)
	launch(func() {
		r.register(context.Background(), chromeMetadata(), "tcp", e.selectG)
		finished <- "регистрация TCP"
	})
	launch(func() {
		r.register(context.Background(), chromeMetadata(), "udp", e.selectG)
		finished <- "регистрация UDP"
	})
	launch(func() { _ = tracked.Close(); finished <- "закрытие TCP" })
	var completed []string
	for len(completed) < 3 {
		select {
		case name := <-finished:
			completed = append(completed, name)
		case <-limit.C:
			t.Fatalf("C2-03: ожидали регистрацию TCP/UDP и закрытие TCP до освобождения записи, завершились только %v за 2 с", completed)
		}
	}
}

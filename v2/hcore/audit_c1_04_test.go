package hcore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/monitoring"
)

func auditC104Instance(t *testing.T) *HiddifyInstance {
	t.Helper()
	old := static
	ctx, cancel := context.WithCancel(context.Background())
	static = &HiddifyInstance{CoreState: CoreStates_STARTED, coreInfoObserver: monitoring.NewBroadcaster[*CoreInfoResponse](ctx), logLevel: LogLevel(100)}
	t.Cleanup(func() { static = old; cancel() })
	return static
}

func TestAudit_C1_04_EmergencyStopHonorsLifecycleLock(t *testing.T) {
	s := auditC104Instance(t)
	s.lock.Lock()
	entered, done := make(chan struct{}), make(chan struct{})
	go func() { close(entered); StopAndAlert(MessageType_UNEXPECTED_ERROR, "audit C1-04"); close(done) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		s.lock.Unlock()
		t.Fatal("C1-04: ожидался запуск аварийной остановки за 2 с, горутина не запустилась")
	}
	// Пока владелец удерживает lock, аварийная остановка не должна завершиться.
	early := false
	select {
	case <-done:
		early = true
	case <-time.After(50 * time.Millisecond):
	}
	s.lock.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("C1-04: ожидалось завершение аварийной остановки после освобождения lock за 2 с, вызов не завершился")
	}
	if early {
		t.Fatal("C1-04: ожидалось ожидание общего lock жизненного цикла, StopAndAlert завершился при занятом lock")
	}
}

// Гонка CoreState между штатной и аварийной остановкой ловится только с -race.
func TestAudit_C1_04_EmergencyAndNormalStopRace(t *testing.T) {
	auditC104Instance(t)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		workers.Add(1)
		go func(emergency bool) {
			defer workers.Done()
			<-start
			for range 200 {
				if emergency {
					StopAndAlert(MessageType_UNEXPECTED_ERROR, "audit C1-04")
				} else {
					Stop()
				}
			}
		}(worker == 0)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	close(start)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("C1-04: ожидалось завершение 200 параллельных остановок за 2 с, вызовы не завершились")
	}
}

package rescuestats

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Как у gRPC: Close и deadlines не прерывают Read, отмена контекста — прерывает.
type auditC201Conn struct {
	net.Conn
	ctx     context.Context
	reading chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *auditC201Conn) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-c.release:
		return 0, io.EOF
	}
}

func (*auditC201Conn) Write(p []byte) (int, error)      { return len(p), nil }
func (*auditC201Conn) Close() error                     { return nil }
func (*auditC201Conn) SetDeadline(time.Time) error      { return nil }
func (*auditC201Conn) SetReadDeadline(time.Time) error  { return nil }
func (*auditC201Conn) SetWriteDeadline(time.Time) error { return nil }

func TestAudit_C2_01_HEADTimeoutCancelsStream(t *testing.T) {
	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &auditC201Conn{ctx: streamCtx, reading: make(chan struct{}), release: make(chan struct{})}
	// Состояние после успешного connect: контекст потока сохранён в pathState.cancel.
	p := &pathState{conn: conn, br: bufio.NewReader(conn), cancel: cancel}
	m := &compareMeasure{r: &compareRun{timeout: 50 * time.Millisecond}, host: "example.test"}
	type result struct {
		sample *int
		panic  any
	}
	done := make(chan result, 1)
	go func() {
		var got result
		defer func() { got.panic = recover(); done <- got }()
		got.sample = m.sample(context.Background(), p)
	}()
	// Освобождаем Read даже при падении и ждём завершения worker до выхода из теста.
	defer func() {
		close(conn.release)
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Error("C2-01: ожидали завершение worker после очистки, он не завершился")
		}
	}()
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	select {
	case <-conn.reading:
	case <-limit.C:
		t.Fatal("C2-01: ожидали начало чтения HEAD, чтение не началось за 2 с")
	}
	select {
	case got := <-done:
		// Сохраняем сигнал для общего cleanup.
		done <- got
		if got.panic != nil {
			t.Fatalf("C2-01: ожидали завершение sample без паники, получено %v", got.panic)
		}
		if got.sample != nil || streamCtx.Err() == nil {
			t.Fatalf("C2-01: ожидали sample=nil и отмену потока по сроку HEAD, получены sample=%v, ошибка контекста=%v", got.sample, streamCtx.Err())
		}
	case <-limit.C:
		t.Fatal("C2-01: ожидали sample=nil и отмену потока по сроку HEAD, Read остался заблокирован через 2 с")
	}
}

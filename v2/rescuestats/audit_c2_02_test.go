package rescuestats

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type auditC202Conn struct {
	net.Conn
	first   atomic.Bool
	reading chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *auditC202Conn) Read(p []byte) (int, error) {
	if c.first.CompareAndSwap(false, true) {
		return copy(p, "HTTP/1.1 200 OK\r\nX:"), nil
	}
	close(c.reading) // bufio уже принял начало ответа и дочитывает заголовки.
	<-c.release
	return 0, io.EOF
}

func (*auditC202Conn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *auditC202Conn) Close() error                   { c.once.Do(func() { close(c.release) }); return nil }
func (*auditC202Conn) SetDeadline(time.Time) error      { return nil }
func (*auditC202Conn) SetReadDeadline(time.Time) error  { return nil }
func (*auditC202Conn) SetWriteDeadline(time.Time) error { return nil }

// Гонка ловится только с -race; паника callback может проявиться и без -race.
func TestAudit_C2_02_HEADCancelConcurrentCleanup(t *testing.T) {
	const childEnv = "RESCUESTATS_AUDIT_C2_02_CHILD"
	if os.Getenv(childEnv) != "1" {
		// recover в worker не может поймать панику чужого context.AfterFunc.
		// Отдельный процесс сохраняет выполнение остальных тестов при такой панике.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAudit_C2_02_HEADCancelConcurrentCleanup$", "-test.count=1", "-test.timeout=3s")
		cmd.Env = append(os.Environ(), childEnv+"=1", "GORACE=atexit_sleep_ms=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Вывод дочерней проверки C2-02:\n%s", out)
			t.Fatalf("C2-02: ожидали отмену HEAD и очистку без гонки, паники и зависания, процесс завершился с ошибкой %v (контекст: %v)", err, ctx.Err())
		}
		return
	}

	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	for i := 0; i < 1000; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		conn := &auditC202Conn{reading: make(chan struct{}), release: make(chan struct{})}
		p := &pathState{conn: conn, br: bufio.NewReader(conn)}
		m := &compareMeasure{r: &compareRun{timeout: time.Minute}, host: "example.test"}
		done := make(chan any, 1)
		go func() {
			defer func() { done <- recover() }()
			_ = m.sample(ctx, p)
		}()
		select {
		case <-conn.reading:
		case <-limit.C:
			_ = conn.Close()
			cancel()
			t.Fatalf("C2-02: ожидали барьер чтения заголовков, повтор %d не дошёл до него за 2 с", i)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; cancel() }()
		go func() { defer wg.Done(); <-start; _ = conn.Close() }()
		close(start)
		select {
		case caught := <-done:
			wg.Wait() // обе операции неблокирующие; callback выполняется отдельно.
			if caught != nil {
				t.Fatalf("C2-02: ожидали очистку sample без паники, повтор %d: %v", i, caught)
			}
		case <-limit.C:
			_ = conn.Close()
			cancel()
			t.Fatalf("C2-02: ожидали завершение sample, повтор %d не завершился за 2 с", i)
		}
	}
}

package rescuestats

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", context.DeadlineExceeded, KindTimeout},
		{"i/o timeout", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, KindTimeout},
		{"windows timeout", errors.New("dial tcp 1.2.3.4:443: connectex: A connection attempt failed because the connected party did not properly respond after a period of time"), KindTimeout},
		{"reset", &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}, KindReset},
		{"windows reset", errors.New("read tcp 10.0.0.2:5000->1.2.3.4:443: wsarecv: An existing connection was forcibly closed by the remote host."), KindReset},
		{"refused", errors.New("dial tcp 127.0.0.1:9: connect: connection refused"), KindRefused},
		{"windows refused", errors.New("dial tcp 127.0.0.1:9: connectex: No connection could be made because the target machine actively refused it."), KindRefused},
		{"dns error", &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}, KindDNS},
		{"dns timeout", &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}, KindDNS},
		{"lookup text", errors.New("lookup failed for example.com: exchange dns-remote: context deadline exceeded"), KindDNS},
		{"nxdomain", errors.New("rcode 3 NXDOMAIN"), KindDNS},
		{"tls", errors.New("tls: handshake failure"), KindTLS},
		{"reality", errors.New("reality verification failed"), KindTLS},
		{"x509", errors.New("x509: certificate signed by unknown authority"), KindTLS},
		{"eof", io.EOF, KindEOF},
		{"unexpected eof", fmt.Errorf("read header: %w", io.ErrUnexpectedEOF), KindEOF},
		{"other", errors.New("something odd"), KindOther},
		{"nil", nil, KindOther},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%s: Classify(%v) = %q, want %q", c.name, c.err, got, c.want)
		}
	}
}

func TestIsIgnorable(t *testing.T) {
	for _, err := range []error{nil, context.Canceled, net.ErrClosed, io.ErrClosedPipe, errors.New("read: use of closed network connection")} {
		if !IsIgnorable(err) {
			t.Errorf("IsIgnorable(%v) = false", err)
		}
	}
	for _, err := range []error{io.EOF, errors.New("connection reset by peer"), context.DeadlineExceeded} {
		if IsIgnorable(err) {
			t.Errorf("IsIgnorable(%v) = true", err)
		}
	}
}

func TestCleanMsg(t *testing.T) {
	got := CleanMsg("open connection to [1.2.3.4,5.6.7.8]:443 using outbound/vless[Мой сервер §hide§]: dial tcp 127.0.0.1:9: connect: connection refused")
	if got != "dial tcp 127.0.0.1:9: connect: connection refused" {
		t.Errorf("prefix not stripped: %q", got)
	}
	got = CleanMsg("connection download closed: read: connection reset by peer")
	if got != "read: connection reset by peer" {
		t.Errorf("copy prefix not stripped: %q", got)
	}
	got = CleanMsg("listen packet connection using  outbound/vless[x]: dial: refused")
	if got != "dial: refused" {
		t.Errorf("listen prefix not stripped: %q", got)
	}
	got = CleanMsg("bad user 3fa85f64-5717-4562-b3fc-2c963f66afa6 rejected")
	if strings.Contains(got, "3fa85f64") {
		t.Errorf("uuid not masked: %q", got)
	}
	long := strings.Repeat("ж", 500)
	got = CleanMsg(long)
	if utf8.RuneCountInString(got) != 300 || !utf8.ValidString(got) {
		t.Errorf("msg not truncated to 300 runes: %d", utf8.RuneCountInString(got))
	}
	got = CleanMsg("\x1b[31mtls: bad\x1b[0m\nmore")
	if got != "tls: bad more" {
		t.Errorf("ansi/newline not cleaned: %q", got)
	}
}

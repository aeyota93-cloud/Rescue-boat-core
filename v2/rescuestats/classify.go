package rescuestats

// Причины ошибок: текст ошибки Go → kind из договора (docs/rescue-redesign-contract.md, раздел 1).
// Ошибки приходят и как error (неудачный dial), и как строка из журнала ядра, поэтому
// главное — разбор текста; типы проверяем только там, где текст неоднозначен.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	KindTimeout    = "timeout"
	KindReset      = "reset"
	KindRefused    = "refused"
	KindDNS        = "dns"
	KindTLS        = "tls"
	KindEOF        = "eof"
	KindStall      = "stall"
	KindOther      = "other"
	KindSuppressed = "suppressed"
)

// Classify сопоставляет ошибку с kind.
func Classify(err error) string {
	if err == nil {
		return KindOther
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return KindDNS
	}
	kind := ClassifyText(err.Error())
	if kind != KindOther {
		return kind
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return KindTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return KindEOF
	}
	return KindOther
}

// Порядок важен: «lookup x: i/o timeout» — это dns, «tls handshake timeout» — это tls.
var textKinds = []struct {
	kind  string
	parts []string
}{
	{KindDNS, []string{"no such host", "nxdomain", "lookup ", "dns", "server misbehaving", "name resolution"}},
	{KindTLS, []string{"tls", "x509", "certificate", "reality"}},
	{KindTimeout, []string{"timeout", "timed out", "deadline exceeded", "did not properly respond"}},
	{KindReset, []string{"connection reset", "forcibly closed", "broken pipe", "connection aborted", "connection was aborted"}},
	{KindRefused, []string{"refused"}},
	{KindEOF, []string{"eof"}},
}

// ClassifyText — то же по тексту (строки журнала).
func ClassifyText(msg string) string {
	lower := strings.ToLower(msg)
	for _, k := range textKinds {
		for _, p := range k.parts {
			if strings.Contains(lower, p) {
				return k.kind
			}
		}
	}
	return KindOther
}

// IsIgnorable — не ошибка сети: соединение закрыла сама программа или ядро.
func IsIgnorable(err error) bool {
	if err == nil {
		return true
	}
	// Не E.IsClosedOrCanceled: он считает «закрытием» и EOF, и таймаут.
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed) {
		return true
	}
	return IsIgnorableText(err.Error())
}

func IsIgnorableText(msg string) bool {
	lower := strings.ToLower(msg)
	for _, p := range []string{
		"use of closed network connection",
		"context canceled",
		"operation was canceled",
		"closed pipe",
		"no_error",
		"response body closed",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// Префиксы sing-box, которые ничего не говорят о причине и содержат имя сервера.
var msgPrefixes = []*regexp.Regexp{
	regexp.MustCompile(`^open (?:packet )?connection to \S+(?: using outbound/[^\[]*\[[^\]]*\](?:\[[^\]]*\])?)?: `),
	regexp.MustCompile(`^listen packet connection using\s*(?:outbound/[^\[]*\[[^\]]*\](?:\[[^\]]*\])?)?: `),
	regexp.MustCompile(`^connection (?:upload|download) (?:closed|handshake|payload): `),
	regexp.MustCompile(`^report handshake success: `),
}

var (
	uuidRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")
)

const maxMsgRunes = 300

// CleanMsg готовит msg: без служебных префиксов, без UUID (это ключи), до 300 символов.
func CleanMsg(msg string) string {
	msg = strings.TrimSpace(ansiRe.ReplaceAllString(msg, ""))
	for changed := true; changed; {
		changed = false
		for _, re := range msgPrefixes {
			if loc := re.FindStringIndex(msg); loc != nil && loc[1] < len(msg) {
				msg = msg[loc[1]:]
				changed = true
			}
		}
	}
	msg = uuidRe.ReplaceAllString(msg, "***")
	msg = strings.ReplaceAll(msg, "\n", " ")
	if utf8.RuneCountInString(msg) > maxMsgRunes {
		r := []rune(msg)
		msg = string(r[:maxMsgRunes])
	}
	return msg
}

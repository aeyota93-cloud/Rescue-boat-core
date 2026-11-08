package rescuestats

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const ProbeUDPTimeout = 4 * time.Second

// ProbeUDP проверяет DNS через выход. Достаточно ответа одной цели.
func ProbeUDP(ctx context.Context, dialer N.Dialer) error {
	return probeUDPTargets(ctx, dialer, []M.Socksaddr{
		M.ParseSocksaddrHostPort("1.1.1.1", 53),
		M.ParseSocksaddrHostPort("8.8.8.8", 53),
	})
}

func probeUDPTargets(ctx context.Context, dialer N.Dialer, targets []M.Socksaddr) error {
	return probeUDPTargetsWithTimeout(ctx, dialer, targets, context.WithTimeout)
}

func probeUDPTargetsWithTimeout(ctx context.Context, dialer N.Dialer, targets []M.Socksaddr, timeout func(context.Context, time.Duration) (context.Context, context.CancelFunc)) error {
	probeCtx, cancel := timeout(ctx, ProbeUDPTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return errors.New("не удалось создать DNS-запрос")
	}
	query := new(dns.Msg)
	query.SetQuestion("www.google.com.", dns.TypeA)
	query.Id = binary.BigEndian.Uint16(id[:])
	wire, err := query.Pack()
	if err != nil {
		return errors.New("не удалось собрать DNS-запрос")
	}
	results := make(chan bool, len(targets))
	var workers sync.WaitGroup
	for _, dst := range targets {
		workers.Add(1)
		go func(dst M.Socksaddr) {
			defer workers.Done()
			ok := false
			defer func() {
				if recover() != nil {
					ok = false
				}
				results <- ok
			}()
			ok = probeUDPTarget(probeCtx, dialer, dst, query, wire)
		}(dst)
	}
	ok := false
	// После успеха отменяем соседей и ждём закрытия всех соединений.
	for range targets {
		if <-results {
			ok = true
			cancel()
		}
	}
	workers.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if ok {
		return nil
	}
	return errors.New("нет корректного ответа UDP")
}

func probeUDPTarget(ctx context.Context, dialer N.Dialer, dst M.Socksaddr, query *dns.Msg, wire []byte) (ok bool) {
	pc, err := dialer.ListenPacket(ctx, dst)
	if err != nil {
		return false
	}
	if ctx.Err() != nil {
		pc.Close()
		return false
	}
	// Закрытие прерывает чтение даже у обёрток без поддержки deadline.
	stop := make(chan struct{})
	closed := make(chan struct{})
	closePanicked := false
	go func() {
		defer close(closed)
		defer func() {
			if recover() != nil {
				closePanicked = true
			}
		}()
		select {
		case <-ctx.Done():
		case <-stop:
		}
		pc.Close()
	}()
	defer func() {
		close(stop)
		<-closed
		if closePanicked {
			ok = false
		}
	}()
	// Многие пакетные соединения выходов sing (hysteria2, vless/xudp) deadline не поддерживают и
	// возвращают ошибку — это не повод сдаваться: срок держит закрытие по ctx выше.
	if deadline, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(deadline)
	}
	if ctx.Err() != nil {
		return false
	}
	if n, err := pc.WriteTo(wire, dst); err != nil || n != len(wire) {
		return false
	}
	buffer := make([]byte, 65535)
	for ctx.Err() == nil {
		n, source, err := pc.ReadFrom(buffer)
		if err != nil {
			return false
		}
		if source == nil || M.SocksaddrFromNet(source).Unwrap() != dst.Unwrap() {
			continue
		}
		var answer dns.Msg
		if answer.Unpack(buffer[:n]) != nil || !answer.Response || answer.Id != query.Id ||
			answer.Opcode != dns.OpcodeQuery || answer.Truncated ||
			(answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeNameError) || len(answer.Question) != 1 {
			continue
		}
		q := answer.Question[0]
		if strings.EqualFold(q.Name, query.Question[0].Name) && q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
			return true
		}
	}
	return false
}

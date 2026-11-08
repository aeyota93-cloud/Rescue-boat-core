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
	probeCtx, cancel := context.WithTimeout(ctx, ProbeUDPTimeout)
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
			results <- probeUDPTarget(probeCtx, dialer, dst, query, wire)
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

func probeUDPTarget(ctx context.Context, dialer N.Dialer, dst M.Socksaddr, query *dns.Msg, wire []byte) bool {
	pc, err := dialer.ListenPacket(ctx, dst)
	if err != nil {
		return false
	}
	// Закрытие прерывает чтение даже у обёрток без поддержки deadline.
	stop := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		select {
		case <-ctx.Done():
		case <-stop:
		}
		pc.Close()
	}()
	defer func() {
		close(stop)
		<-closed
	}()
	deadline, _ := ctx.Deadline()
	if err := pc.SetDeadline(deadline); err != nil {
		return false
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

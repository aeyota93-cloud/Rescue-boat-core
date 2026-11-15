package config

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
)

type auditC102Transport struct {
	adapter.DNSTransport
	tag   string
	ip    net.IP
	calls int
}

func (s *auditC102Transport) Tag() string { return s.tag }
func (s *auditC102Transport) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	s.calls++
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: s.ip}}
	return r, nil
}

func TestAudit_C1_02_BuiltDNSHonorsTTLAndTransport(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(fmt.Sprintf("independent=%t", independent), func(t *testing.T) {
			h := auditC1Options()
			h.IndependentDNSCache = independent
			var built option.Options
			ips := map[string][]string{}
			if err := setDns(&built, h, &ips); err != nil {
				t.Fatalf("C1-02: ожидалась сборка DNS без ошибки, получено %v", err)
			}
			o := built.DNS.DNSClientOptions
			client := sdns.NewClient(sdns.ClientOptions{DisableCache: o.DisableCache, DisableExpire: o.DisableExpire, IndependentCache: o.IndependentCache, Timeout: time.Second})
			defer client.ClearCache()
			transport := &auditC102Transport{tag: "direct", ip: net.IPv4(192, 0, 2, 1)}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			query := func(tr *auditC102Transport) *dns.Msg {
				q := new(dns.Msg)
				q.SetQuestion("ttl.audit.invalid.", dns.TypeA)
				// RewriteTTL намеренно отсутствует: проверяем исходный TTL транспорта.
				r, err := client.Exchange(ctx, tr, q, adapter.DNSQueryOptions{}, nil)
				if err != nil {
					t.Fatalf("C1-02: ожидался DNS-ответ из памяти, получено %v", err)
				}
				return r
			}
			query(transport)
			query(transport)
			if transport.calls != 1 {
				t.Fatalf("C1-02: до истечения TTL ожидался один запрос, получено %d", transport.calls)
			}
			time.Sleep(1200 * time.Millisecond)
			query(transport)
			if transport.calls != 2 {
				t.Errorf("C1-02: после TTL=1 с ожидалось 2 запроса к транспорту, получено %d (DisableExpire=%t)", transport.calls, o.DisableExpire)
			}
			if o.IndependentCache {
				vpn := &auditC102Transport{tag: "vpn", ip: net.IPv4(192, 0, 2, 2)}
				r := query(vpn)
				if vpn.calls != 1 || len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.Equal(vpn.ip) {
					t.Errorf("C1-02: при независимом кеше ожидался ответ VPN, получено %v, запросов %d", r.Answer, vpn.calls)
				}
			}
		})
	}
}

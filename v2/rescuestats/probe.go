package rescuestats

// Замеры качества раз в 60 секунд: 5 HTTP-запросов к connection-test-url подряд через
// выбранный VPN-путь и через direct (таймаут 3 с, null — потеря) и счётчики за минуту.
// Запросы идут прямо через outbound, мимо маршрутизатора: в errors и в счётчики они не попадают,
// а их строки журнала (DNS) отсеиваются по собственному номеру в контексте.

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

const (
	ProbeSamples      = 5
	ProbeTimeout      = 3 * time.Second
	defaultProbeURL   = "http://cp.cloudflare.com/"
	ownIDGraceSeconds = 30
)

// probeFunc — один запрос; подменяется в тестах.
type probeFunc func(ctx context.Context, link string, dialer N.Dialer) (time.Duration, error)

func urlTestProbe(ctx context.Context, link string, dialer N.Dialer) (time.Duration, error) {
	ms, err := urltest.URLTest(ctx, link, dialer)
	return time.Duration(ms) * time.Millisecond, err
}

func (r *run) qualityLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(QualityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		r.qualityCycle(urlTestProbe)
	}
}

// qualityCycle — одна минута: счётчики и оба замера с одним t.
func (r *run) qualityCycle(probe probeFunc) {
	at := r.now()
	counters := r.takeCounters(at)
	paths := []struct {
		name   string
		dialer adapter.Outbound
	}{
		{RouteVPN, r.vpnOutbound()},
		{RouteDirect, r.directOutbound()},
	}
	results := make([][]*int, len(paths))
	var wg sync.WaitGroup
	for i, p := range paths {
		if p.dialer == nil || r.opts.NoProbe {
			continue
		}
		wg.Add(1)
		go func(i int, dialer N.Dialer) {
			defer wg.Done()
			results[i] = r.probePath(dialer, probe)
		}(i, p.dialer)
	}
	wg.Wait()
	for i, p := range paths {
		// При остановке посреди замера неполные выборки не пишем.
		if results[i] == nil || r.ctx.Err() != nil {
			continue
		}
		r.store.AddQuality(ProbeRecord{V: FormatVersion, T: at.UnixMilli(), Type: "probe", Path: p.name, Samples: results[i]}, at)
	}
	r.store.AddQuality(counters, at)
}

func (r *run) takeCounters(at time.Time) CountersRecord {
	start, fail := r.dnsStart.Swap(0), r.dnsFail.Swap(0)
	ok := start - fail
	if ok < 0 {
		ok = 0
	}
	return CountersRecord{
		V:       FormatVersion,
		T:       at.UnixMilli(),
		Type:    "counters",
		Conns:   r.conns.Swap(0),
		Errs:    r.errs.Swap(0),
		DNSOk:   ok,
		DNSFail: fail,
	}
}

func (r *run) probePath(dialer N.Dialer, probe probeFunc) []*int {
	link := r.opts.TestURL
	if link == "" {
		link = defaultProbeURL
	}
	samples := make([]*int, 0, ProbeSamples)
	for i := 0; i < ProbeSamples; i++ {
		if r.ctx.Err() != nil {
			return nil
		}
		ctx := r.ownContext()
		ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
		d, err := probe(ctx, link, dialer)
		cancel()
		if err != nil || d <= 0 || d > ProbeTimeout {
			samples = append(samples, nil)
			continue
		}
		ms := int(d / time.Millisecond)
		if ms == 0 {
			ms = 1
		}
		samples = append(samples, &ms)
	}
	return samples
}

// ownContext — контекст с новым номером журнала, помеченным как «свой».
func (r *run) ownContext() context.Context {
	ctx := log.ContextWithNewID(r.ctx)
	id, _ := log.IDFromContext(ctx)
	r.access.Lock()
	r.ownIDs[id.ID] = r.now().Add(ownIDGraceSeconds * time.Second)
	r.access.Unlock()
	return ctx
}

func (r *run) vpnOutbound() adapter.Outbound {
	if r.outbounds == nil {
		return nil
	}
	if r.opts.VPNOutbound != "" {
		if ob, ok := r.outbounds.Outbound(r.opts.VPNOutbound); ok {
			return ob
		}
	}
	return r.outbounds.Default()
}

func (r *run) directOutbound() adapter.Outbound {
	if r.outbounds == nil {
		return nil
	}
	if r.opts.DirectOutbound != "" {
		if ob, ok := r.outbounds.Outbound(r.opts.DirectOutbound); ok {
			return ob
		}
	}
	for _, ob := range r.outbounds.Outbounds() {
		if ob.Type() == C.TypeDirect {
			return ob
		}
	}
	return nil
}

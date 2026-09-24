package scanner

import (
	"context"
	"fmt"
	"net"

	"github.com/velvet1way/recon-agent/internal/queue"
)

// ResolveDNS резолвит поддомен в IP-адреса штатным резолвером Go
// (без внешних зависимостей), пишет связи RESOLVES_TO и ставит
// follow-up задачи http_probe (на хост) и port_scan (на каждый IP).
func (s *Scanner) ResolveDNS(ctx context.Context, host string) error {
	if d := s.guard.Check(host); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", host, d.Reason)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		// NXDOMAIN и подобное — не фатально, просто нет записей.
		s.log.Debug("резолв без результата", "host", host, "err", err)
		return nil
	}

	probeQueued := false
	for _, ipAddr := range ips {
		ip := ipAddr.IP.String()
		// IP тоже через scope-guard: поддомен в скоупе может резолвиться
		// в чужую инфраструктуру (CDN, шаред-хостинг).
		if !s.guard.Allowed(ip) {
			s.log.Debug("IP вне скоупа, пропуск", "host", host, "ip", ip)
			continue
		}
		if err := s.store.AddResolution(ctx, host, ip, s.runID); err != nil {
			s.log.Error("запись резолва в граф", "host", host, "ip", ip, "err", err)
			continue
		}
		if s.next != nil {
			s.next.Enqueue(queue.Task{Kind: queue.KindPortScan, Target: ip})
		}
		probeQueued = true
	}

	// HTTP-проб ставим один раз на хост (httpx сам переберёт схемы/порты).
	if probeQueued && s.next != nil {
		s.next.Enqueue(queue.Task{Kind: queue.KindHTTPProbe, Target: host})
	}
	s.log.Info("резолв завершён", "host", host, "ips", len(ips))
	return nil
}

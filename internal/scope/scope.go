// Package scope реализует scope-guard: проверку, что цель разрешена
// границами программы bug bounty. Используется дважды — на уровне
// оркестратора (перед постановкой задачи) и исполнителя (перед запуском
// инструмента), чтобы галлюцинация LLM не привела к действию вне скоупа.
package scope

import (
	"fmt"
	"net"
	"strings"

	"github.com/velvet1way/recon-agent/internal/config"
)

// Decision — результат проверки цели.
type Decision struct {
	Allowed bool
	Reason  string
}

// Guard проверяет цели против скоупа программы.
type Guard struct {
	inDomains  []string
	outDomains []string
	inCIDRs    []*net.IPNet
	outCIDRs   []*net.IPNet
	wildcards  bool
}

// New строит Guard из scope-конфига.
func New(s *config.Scope) (*Guard, error) {
	g := &Guard{
		inDomains:  normalizeDomains(s.InScope.Domains),
		outDomains: normalizeDomains(s.OutOfScope.Domains),
		wildcards:  s.InScope.Wildcards,
	}

	var err error
	if g.inCIDRs, err = parseCIDRs(s.InScope.CIDRs); err != nil {
		return nil, fmt.Errorf("in_scope CIDR: %w", err)
	}
	if g.outCIDRs, err = parseCIDRs(s.OutOfScope.CIDRs); err != nil {
		return nil, fmt.Errorf("out_of_scope CIDR: %w", err)
	}
	return g, nil
}

// Check возвращает решение для произвольной цели (домен или IP).
// out_of_scope имеет приоритет над in_scope.
func (g *Guard) Check(target string) Decision {
	t := strings.TrimSpace(strings.ToLower(target))
	if t == "" {
		return Decision{false, "пустая цель"}
	}

	if ip := net.ParseIP(t); ip != nil {
		return g.checkIP(ip)
	}
	return g.checkDomain(t)
}

// Allowed — краткая форма Check для мест, где нужен только флаг.
func (g *Guard) Allowed(target string) bool {
	return g.Check(target).Allowed
}

func (g *Guard) checkDomain(d string) Decision {
	for _, od := range g.outDomains {
		if matchDomain(od, d, false) {
			return Decision{false, fmt.Sprintf("домен %q явно вне скоупа (out_of_scope: %s)", d, od)}
		}
	}
	for _, id := range g.inDomains {
		if matchDomain(id, d, g.wildcards) {
			return Decision{true, fmt.Sprintf("домен %q в скоупе (in_scope: %s)", d, id)}
		}
	}
	return Decision{false, fmt.Sprintf("домен %q не входит ни в один in_scope шаблон", d)}
}

func (g *Guard) checkIP(ip net.IP) Decision {
	for _, oc := range g.outCIDRs {
		if oc.Contains(ip) {
			return Decision{false, fmt.Sprintf("IP %s явно вне скоупа (out_of_scope: %s)", ip, oc)}
		}
	}
	for _, ic := range g.inCIDRs {
		if ic.Contains(ip) {
			return Decision{true, fmt.Sprintf("IP %s в скоупе (in_scope: %s)", ip, ic)}
		}
	}
	return Decision{false, fmt.Sprintf("IP %s не входит ни в один in_scope CIDR", ip)}
}

// matchDomain сопоставляет цель с шаблоном.
// Шаблон "*.example.com" покрывает поддомены; если allowWildcard=true,
// он также покрывает сам "example.com".
func matchDomain(pattern, target string, allowWildcard bool) bool {
	if pattern == target {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		if target == base {
			return allowWildcard
		}
		return strings.HasSuffix(target, "."+base)
	}
	return false
}

func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func parseCIDRs(in []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("некорректный CIDR %q: %w", c, err)
		}
		out = append(out, ipnet)
	}
	return out, nil
}

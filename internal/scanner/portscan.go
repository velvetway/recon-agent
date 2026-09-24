package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
)

// nmapRun — минимальная модель XML-вывода nmap (-oX).
type nmapRun struct {
	Hosts []struct {
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name string `xml:"name,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// nmapArgs собирает аргументы nmap: топ-100 портов, лёгкое определение
// сервиса, и потолок скорости --max-rate (пакетов/с) из конфига, чтобы не
// превышать лимит программы.
func nmapArgs(ip string, cfg Config) []string {
	args := []string{
		"-Pn",
		"--top-ports", "100",
		"-sV", "--version-light",
		"-T3",
	}
	if cfg.PerTargetRPS > 0 {
		args = append(args, "--max-rate", strconv.Itoa(cfg.PerTargetRPS))
	}
	return append(args, "-oX", "-", ip)
}

// PortScan запускает nmap по IP (top-100 портов, определение сервисов),
// пишет открытые порты в граф как Port.
func (s *Scanner) PortScan(ctx context.Context, ip string) error {
	if d := s.guard.Check(ip); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", ip, d.Reason)
	}

	out, err := exec.CommandContext(ctx, "nmap", nmapArgs(ip, s.cfg)...).Output()
	if err != nil {
		return fmt.Errorf("запуск nmap: %w", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(out, &run); err != nil {
		return fmt.Errorf("разбор XML nmap: %w", err)
	}

	found := 0
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			if err := s.store.AddPort(ctx, ip, p.PortID, p.Protocol, p.Service.Name, s.runID); err != nil {
				s.log.Error("запись порта в граф", "ip", ip, "port", p.PortID, "err", err)
				continue
			}
			s.observe(ctx, ip, "nmap", "open_port",
				fmt.Sprintf("%d/%s", p.PortID, p.Protocol), p.Service.Name)
			found++
		}
	}
	s.log.Info("nmap завершён", "ip", ip, "open_ports", found)
	return nil
}

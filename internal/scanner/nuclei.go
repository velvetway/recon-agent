package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/velvet1way/recon-agent/internal/queue"
)

// nucleiResult — подмножество JSONL-вывода nuclei. Ключевое — classification:
// nuclei сам отдаёт CWE и CVE, поэтому его находки ложатся в слой «сигнал →
// CWE» напрямую, без угадывания правилами.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Type       string `json:"type"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification struct {
			CWE []string `json:"cwe-id"`
			CVE []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
}

// VulnScan запускает nuclei по URL. Требует профиль active (активная проверка
// уязвимостей). Каждая находка пишется наблюдением kind="vuln", а её CWE и CVE
// — отдельными наблюдениями kind="finding_cwe"/"finding_cve", чтобы отчёт мог
// опереться на классификацию самого nuclei.
func (s *Scanner) VulnScan(ctx context.Context, t queue.Task) error {
	if d := s.guard.Check(t.Target); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", t.Target, d.Reason)
	}
	cmd := exec.CommandContext(ctx, "nuclei", nucleiArgs(taskURL(t), s.cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск nuclei: %w", err)
	}

	found := 0
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}
		asset := nr.asset()
		if asset == "" || !s.guard.Allowed(asset) {
			continue
		}
		ev := strings.TrimSpace(nr.Info.Severity + " | " + nr.Info.Name + " | " + nr.MatchedAt)
		s.observe(ctx, asset, "nuclei", "vuln", nr.TemplateID, ev)
		for _, cwe := range nr.Info.Classification.CWE {
			s.observe(ctx, asset, "nuclei", "finding_cwe", cwe, nr.TemplateID+" | "+nr.Info.Severity)
		}
		for _, cve := range nr.Info.Classification.CVE {
			s.observe(ctx, asset, "nuclei", "finding_cve", cve, nr.TemplateID+" | "+nr.Info.Severity)
		}
		found++
	}
	if err := cmd.Wait(); err != nil {
		// nuclei возвращает ненулевой код, когда находок нет, — не считаем ошибкой.
		s.log.Debug("nuclei завершился с кодом ошибки", "target", t.Target, "err", err)
	}
	s.log.Info("nuclei завершён", "target", t.Target, "findings", found)
	return nil
}

// asset возвращает хост находки для scope-проверки и привязки наблюдения.
func (n nucleiResult) asset() string {
	if n.Host != "" {
		return stripScheme(n.Host)
	}
	return stripScheme(n.MatchedAt)
}

// nucleiArgs собирает аргументы nuclei: цель, JSONL, заголовки, лимит скорости.
func nucleiArgs(url string, cfg Config) []string {
	args := []string{"-u", url, "-jsonl", "-silent"}
	for _, h := range cfg.HTTPHeaders {
		args = append(args, "-H", h.String())
	}
	if cfg.PerTargetRPS > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.PerTargetRPS))
	}
	return args
}

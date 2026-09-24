package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/velvet1way/recon-agent/internal/queue"
)

// PassiveURLs собирает URL цели из веб-архивов через gau (пассивно, саму цель
// не трогает). Найденные in-scope URL пишет наблюдениями kind="url".
func (s *Scanner) PassiveURLs(ctx context.Context, domain string) error {
	if d := s.guard.Check(domain); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", domain, d.Reason)
	}
	// gau ходит в архивы (Wayback, Common Crawl), а не в цель — заголовки и
	// лимит скорости цели тут ни при чём.
	cmd := exec.CommandContext(ctx, "gau", "--subs", "--threads", "5", domain)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск gau: %w", err)
	}

	found := s.scanURLLines(ctx, stdout, "gau")
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("gau завершился с ошибкой: %w", err)
	}
	s.log.Info("gau завершён", "domain", domain, "urls_in_scope", found)
	return nil
}

// Crawl обходит сайт через katana и собирает URL и эндпоинты. Требует профиль
// light (обычные HTTP-запросы к цели); использует заголовки и лимит скорости.
func (s *Scanner) Crawl(ctx context.Context, t queue.Task) error {
	if d := s.guard.Check(t.Target); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", t.Target, d.Reason)
	}
	cmd := exec.CommandContext(ctx, "katana", katanaArgs(taskURL(t), s.cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск katana: %w", err)
	}

	found := 0
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var kr katanaResult
		if err := json.Unmarshal([]byte(line), &kr); err != nil {
			continue
		}
		u := kr.url()
		if u == "" || !s.guard.Allowed(stripScheme(u)) {
			continue
		}
		s.observe(ctx, stripScheme(u), "katana", "url", u, "crawl")
		found++
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("katana завершился с ошибкой: %w", err)
	}
	s.log.Info("katana завершён", "target", t.Target, "urls_in_scope", found)
	return nil
}

// scanURLLines читает URL по строкам, пишет in-scope наблюдениями kind="url".
func (s *Scanner) scanURLLines(ctx context.Context, r io.Reader, tool string) int {
	found := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u == "" {
			continue
		}
		host := stripScheme(u)
		if !s.guard.Allowed(host) {
			continue
		}
		s.observe(ctx, host, tool, "url", u, "archive")
		found++
	}
	return found
}

// katanaResult — гибкая модель JSONL-вывода katana: URL может лежать в поле
// url или в request.endpoint (зависит от версии).
type katanaResult struct {
	URL     string `json:"url"`
	Request struct {
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

func (k katanaResult) url() string {
	if k.URL != "" {
		return k.URL
	}
	return k.Request.Endpoint
}

// katanaArgs собирает аргументы katana: seed-URL, JSONL, глубина, заголовки и
// лимит скорости.
func katanaArgs(url string, cfg Config) []string {
	args := []string{"-u", url, "-jsonl", "-silent", "-d", "2"}
	for _, h := range cfg.HTTPHeaders {
		args = append(args, "-H", h.String())
	}
	if cfg.PerTargetRPS > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.PerTargetRPS))
	}
	return args
}

// taskURL возвращает полный URL задачи: t.URL, если задан, иначе https://target.
func taskURL(t queue.Task) string {
	if t.URL != "" {
		return t.URL
	}
	return "https://" + t.Target
}

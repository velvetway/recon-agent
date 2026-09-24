package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/velvet1way/recon-agent/internal/graph"
)

// httpxResult — подмножество JSONL-вывода httpx (projectdiscovery).
type httpxResult struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
}

// HTTPProbe запускает httpx по хосту: определяет живые HTTP-сервисы,
// код ответа, заголовок, веб-сервер и tech-стек, пишет в граф как Service.
func (s *Scanner) HTTPProbe(ctx context.Context, host string) error {
	if d := s.guard.Check(host); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", host, d.Reason)
	}

	cmd := exec.CommandContext(ctx, "httpx", httpxArgs(host, s.cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск httpx: %w", err)
	}

	found := 0
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r httpxResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		// URL httpx мог развернуть на другой хост при редиректе —
		// подстрахуемся scope-guard'ом по исходному входу.
		if !s.guard.Allowed(stripScheme(r.URL)) && !s.guard.Allowed(host) {
			continue
		}
		if err := s.store.AddHTTPService(ctx, graph.HTTPService{
			Host:       host,
			URL:        r.URL,
			StatusCode: r.StatusCode,
			Title:      r.Title,
			WebServer:  r.WebServer,
			Tech:       r.Tech,
		}, s.runID); err != nil {
			s.log.Error("запись HTTP-сервиса в граф", "host", host, "err", err)
			continue
		}
		// Наблюдения: сам сервис, веб-сервер и каждая технология — отдельными
		// фактами, чтобы правила фазы 5 могли ссылаться на них по одному.
		s.observe(ctx, host, "httpx", "http_service", r.URL, fmt.Sprintf("%d %s", r.StatusCode, r.Title))
		if r.WebServer != "" {
			s.observe(ctx, host, "httpx", "webserver", r.WebServer, r.URL)
		}
		for _, tech := range r.Tech {
			s.observe(ctx, host, "httpx", "tech", tech, r.URL)
		}
		found++
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("httpx завершился с ошибкой: %w", err)
	}
	s.log.Info("httpx завершён", "host", host, "services", found)
	return nil
}

// httpxArgs собирает аргументы httpx: базовый пробы + обязательные заголовки
// программы (-H) + лимит скорости (-rl), спущенный из конфига.
func httpxArgs(host string, cfg Config) []string {
	args := []string{
		"-u", host,
		"-json",
		"-silent",
		"-title", "-tech-detect", "-web-server", "-status-code",
		"-no-color",
	}
	for _, h := range cfg.HTTPHeaders {
		args = append(args, "-H", h.String())
	}
	if cfg.PerTargetRPS > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.PerTargetRPS))
	}
	return args
}

// stripScheme убирает схему и путь, оставляя хост для scope-проверки.
func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	return u
}

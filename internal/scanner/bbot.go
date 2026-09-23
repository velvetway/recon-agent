// Package scanner запускает внешние инструменты разведки (BBOT и др.)
// и сохраняет результат в граф. Здесь находится ВТОРАЯ проверка
// scope-guard — на уровне исполнителя, перед фактическим запуском.
package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/velvet1way/recon-agent/internal/graph"
	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scope"
)

// Enqueuer ставит follow-up задачи (реализуется оркестратором,
// который проверяет scope-guard и дедуплицирует).
type Enqueuer interface {
	Enqueue(t queue.Task) bool
}

// Scanner исполняет задачи разведки.
type Scanner struct {
	guard  *scope.Guard
	store  *graph.Store
	next   Enqueuer
	outDir string
	log    *slog.Logger
}

// New создаёт исполнитель.
func New(guard *scope.Guard, store *graph.Store, next Enqueuer, outDir string, log *slog.Logger) *Scanner {
	return &Scanner{
		guard:  guard,
		store:  store,
		next:   next,
		outDir: outDir,
		log:    log,
	}
}

// bbotEvent — минимальная форма NDJSON-события BBOT.
type bbotEvent struct {
	Type   string `json:"type"`
	Data   any    `json:"data"`
	Module string `json:"module"`
}

// SubdomainEnum запускает пассивное перечисление поддоменов через BBOT.
func (s *Scanner) SubdomainEnum(ctx context.Context, target string) error {
	// ВТОРАЯ проверка scope-guard — на уровне исполнителя.
	if d := s.guard.Check(target); !d.Allowed {
		return fmt.Errorf("scope-guard заблокировал цель %q: %s", target, d.Reason)
	}

	if err := os.MkdirAll(s.outDir, 0o755); err != nil {
		return fmt.Errorf("создание outDir: %w", err)
	}
	scanDir := filepath.Join(s.outDir, sanitize(target))

	// Пассивный, безопасный пресет: без активной эксплуатации.
	args := []string{
		"-t", target,
		"-p", "subdomain-enum",
		"-o", scanDir,
		"-om", "json",
		"-y",          // не спрашивать подтверждение
		"--no-deps",   // не переустанавливать зависимости на каждом запуске
	}

	cmd := exec.CommandContext(ctx, "bbot", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск bbot: %w", err)
	}

	s.log.Info("bbot запущен", "target", target, "preset", "subdomain-enum")

	found := 0
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var ev bbotEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue // не-JSON строки прогресса игнорируем
		}
		if ev.Type != "DNS_NAME" {
			continue
		}
		sub, ok := ev.Data.(string)
		if !ok {
			continue
		}
		// Каждый найденный поддомен ещё раз через scope-guard —
		// BBOT может выдать связанные, но вне-скоуповые имена.
		if !s.guard.Allowed(sub) {
			continue
		}
		if err := s.store.AddSubdomain(ctx, target, sub, ev.Module); err != nil {
			s.log.Error("запись поддомена в граф", "sub", sub, "err", err)
			continue
		}
		found++
		// Follow-up: резолвим найденный поддомен в IP.
		if s.next != nil {
			s.next.Enqueue(queue.Task{Kind: "dns_resolve", Target: sub})
		}
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("bbot завершился с ошибкой: %w", err)
	}
	s.log.Info("bbot завершён", "target", target, "found_in_scope", found)
	return nil
}

func sanitize(s string) string {
	r := strings.NewReplacer("*", "_", "/", "_", ":", "_", " ", "_")
	return r.Replace(s)
}

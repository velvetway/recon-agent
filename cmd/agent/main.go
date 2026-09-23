// Command agent — точка входа Recon-агента.
//
// Использование:
//
//	agent -scope configs/scope.yaml            # запустить разведку
//	agent -scope configs/scope.yaml -check host # проверить цель scope-guard'ом
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/graph"
	"github.com/velvet1way/recon-agent/internal/orchestrator"
	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scanner"
	"github.com/velvet1way/recon-agent/internal/scope"
)

func main() {
	var (
		scopePath = flag.String("scope", "configs/scope.yaml", "путь к scope-конфигу")
		checkOnly = flag.String("check", "", "проверить цель через scope-guard и выйти")
		outDir    = flag.String("out", "output", "директория для результатов сканов")
		neo4jURI  = flag.String("neo4j", envOr("NEO4J_URI", "neo4j://localhost:7687"), "URI Neo4j")
		neo4jUser = flag.String("neo4j-user", envOr("NEO4J_USER", "neo4j"), "пользователь Neo4j")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sc, err := config.LoadScope(*scopePath)
	if err != nil {
		fatal(log, "загрузка scope", err)
	}
	guard, err := scope.New(sc)
	if err != nil {
		fatal(log, "инициализация scope-guard", err)
	}

	// Режим проверки одной цели — без Neo4j и сканов.
	if *checkOnly != "" {
		d := guard.Check(*checkOnly)
		status := "ЗАБЛОКИРОВАНО"
		if d.Allowed {
			status = "РАЗРЕШЕНО"
		}
		fmt.Printf("%s: %s\n%s\n", *checkOnly, status, d.Reason)
		if !d.Allowed {
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := graph.New(ctx, graph.Config{
		URI:      *neo4jURI,
		Username: *neo4jUser,
		Password: envOr("NEO4J_PASSWORD", "password"),
	})
	if err != nil {
		fatal(log, "подключение к neo4j", err)
	}
	defer store.Close(ctx)

	if err := store.InitSchema(ctx); err != nil {
		fatal(log, "инициализация схемы графа", err)
	}
	if err := store.UpsertProgram(ctx, sc.Program, sc.Platform); err != nil {
		fatal(log, "запись программы в граф", err)
	}

	scan := scanner.New(guard, store, *outDir, log)

	// Обработчик очереди диспетчеризует задачи по видам.
	handler := func(ctx context.Context, t queue.Task) error {
		switch t.Kind {
		case "subdomain_enum":
			return scan.SubdomainEnum(ctx, t.Target)
		default:
			return fmt.Errorf("неизвестный вид задачи: %s", t.Kind)
		}
	}

	limiter := queue.NewRateLimiter(sc.RateLimits.GlobalRPS, sc.RateLimits.PerTargetRPS)
	q := queue.New(sc.RateLimits.MaxConcurrent, limiter, handler, log)
	q.Start(ctx)

	orch := orchestrator.New(guard, q, log)
	roots := sc.RootDomains()
	log.Info("старт разведки", "program", sc.Program, "roots", roots)
	orch.SeedFromScope(ctx, roots)

	<-ctx.Done()
	log.Info("остановка, ждём завершения задач")
	q.Shutdown()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "err", err)
	os.Exit(1)
}

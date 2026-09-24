// Command agent — точка входа Recon-агента.
//
// Использование:
//
//	agent -scope configs/scope.yaml            # запустить разведку
//	agent -scope configs/scope.yaml -check host # проверить цель scope-guard'ом
//	agent -cwe-load data/cwe/cwe.json           # загрузить каталог CWE в Neo4j
//	agent -scope-import targets.txt -scope-out configs/scope.yaml -program Example
//	pbpaste | agent -scope-import -             # скоуп из буфера → YAML в stdout
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/cwe"
	"github.com/velvet1way/recon-agent/internal/graph"
	"github.com/velvet1way/recon-agent/internal/orchestrator"
	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scanner"
	"github.com/velvet1way/recon-agent/internal/scope"
	"github.com/velvet1way/recon-agent/internal/scopeimport"
)

func main() {
	var (
		scopePath = flag.String("scope", "configs/scope.yaml", "путь к scope-конфигу")
		checkOnly = flag.String("check", "", "проверить цель через scope-guard и выйти")
		outDir    = flag.String("out", "output", "директория для результатов сканов")
		neo4jURI  = flag.String("neo4j", envOr("NEO4J_URI", "neo4j://localhost:7687"), "URI Neo4j")
		neo4jUser = flag.String("neo4j-user", envOr("NEO4J_USER", "neo4j"), "пользователь Neo4j")
		cweLoad   = flag.String("cwe-load", "", "загрузить каталог CWE (data/cwe/cwe.json) в Neo4j и выйти")

		scopeImport = flag.String("scope-import", "", "собрать scope.yaml из текста: путь к файлу или '-' для stdin")
		importOut   = flag.String("scope-out", "", "куда записать scope.yaml при -scope-import (по умолчанию stdout)")
		program     = flag.String("program", "", "название программы для -scope-import")
		platform    = flag.String("platform", "", "платформа для -scope-import (hackerone, bugcrowd, standoff365...)")
		assumeYes   = flag.Bool("yes", false, "не спрашивать подтверждения при записи файла")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Импорт скоупа из текста — до загрузки scope.yaml, которого ещё может не быть.
	if *scopeImport != "" {
		if err := importScope(*scopeImport, *importOut, *program, *platform, *assumeYes); err != nil {
			fatal(log, "импорт скоупа", err)
		}
		return
	}

	neo4jCfg := graph.Config{
		URI:      *neo4jURI,
		Username: *neo4jUser,
		Password: envOr("NEO4J_PASSWORD", "password"),
	}

	// Загрузка каталога CWE — справочник, скоуп для неё не нужен.
	if *cweLoad != "" {
		if err := loadCWE(log, neo4jCfg, *cweLoad); err != nil {
			fatal(log, "загрузка каталога CWE", err)
		}
		return
	}

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

	store, err := graph.New(ctx, neo4jCfg)
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

	runID := newRunID()
	if err := store.StartRun(ctx, runID, sc.Program, string(sc.Profile)); err != nil {
		fatal(log, "запись прогона в граф", err)
	}

	// scan объявляем заранее: обработчик очереди ссылается на него,
	// а сам scan создаётся после оркестратора (цикл зависимостей).
	var scan *scanner.Scanner

	// Обработчик очереди диспетчеризует задачи по видам.
	handler := func(ctx context.Context, t queue.Task) error {
		switch t.Kind {
		case queue.KindSubdomainEnum:
			return scan.SubdomainEnum(ctx, t.Target)
		case queue.KindDNSResolve:
			return scan.ResolveDNS(ctx, t.Target)
		case queue.KindHTTPProbe:
			return scan.HTTPProbe(ctx, t.Target)
		case queue.KindPortScan:
			return scan.PortScan(ctx, t.Target)
		default:
			return fmt.Errorf("неизвестный вид задачи: %s", t.Kind)
		}
	}

	limiter := queue.NewRateLimiter(sc.RateLimits.GlobalRPS, sc.RateLimits.PerTargetRPS)
	q := queue.New(sc.RateLimits.MaxConcurrent, limiter, handler, log)
	q.Start(ctx)

	orch := orchestrator.New(guard, q, sc.Profile, log)
	scan = scanner.New(guard, store, orch, *outDir, runID, log)
	roots := sc.RootDomains()
	log.Info("старт разведки", "program", sc.Program, "profile", sc.Profile, "run", runID, "roots", roots)
	orch.SeedFromScope(ctx, roots)

	// Прогон завершается сам, когда очередь опустела; Ctrl+C прерывает досрочно.
	if q.WaitIdle(ctx) {
		log.Info("разведка завершена: очередь пуста", "run", runID)
	} else {
		log.Info("прервано, ждём завершения текущих задач", "run", runID)
	}
	q.Shutdown()
}

// newRunID — идентификатор прогона по времени старта в UTC.
func newRunID() string {
	return "run-" + time.Now().UTC().Format("20060102-150405")
}

// importScope разбирает скоуп из текста, показывает сводку в stderr и пишет
// YAML в stdout или в файл. Перед записью файла спрашивает подтверждение
// (или требует -yes, если спросить нельзя).
func importScope(src, dst, program, platform string, yes bool) error {
	var in io.Reader = os.Stdin
	name := "stdin"
	if src != "-" {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		in, name = f, src
	}

	rep, err := scopeimport.Parse(in)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, rep.Summary())
	if len(rep.In) == 0 {
		return fmt.Errorf("в скоупе нет ни одной цели — проверьте входной текст")
	}

	if program == "" {
		if roots := rep.Scope("", "").RootDomains(); len(roots) > 0 {
			program = roots[0]
		}
	}
	out, err := scopeimport.RenderYAML(rep.Scope(program, platform), name)
	if err != nil {
		return err
	}

	if dst == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if !yes {
		// Спросить можно, только если stdin — терминал и скоуп пришёл не из него.
		if src == "-" || !stdinIsTerminal() {
			return fmt.Errorf("запись в %s требует подтверждения: добавьте -yes", dst)
		}
		fmt.Fprintf(os.Stderr, "Записать скоуп в %s? [y/N] ", dst)
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" && a != "д" && a != "да" {
			return fmt.Errorf("отменено, файл не записан")
		}
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Скоуп записан в %s\n", dst)
	return nil
}

// stdinIsTerminal — грубая проверка без внешних зависимостей: символьное
// устройство, но не /dev/null (он тоже символьное устройство).
func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(st, null) {
		return false
	}
	return true
}

// loadCWE читает каталог, проверяет его и загружает в граф.
func loadCWE(log *slog.Logger, cfg graph.Config, path string) error {
	cat, err := cwe.Load(path)
	if err != nil {
		return err
	}
	log.Info("каталог CWE прочитан", "version", cat.Version, "records", cat.Len())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := graph.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("подключение к neo4j: %w", err)
	}
	defer store.Close(ctx)

	if err := store.InitSchema(ctx); err != nil {
		return fmt.Errorf("инициализация схемы графа: %w", err)
	}
	st, err := store.LoadCWECatalog(ctx, cat)
	if err != nil {
		return err
	}
	fmt.Printf("CWE v%s загружен в граф: %d узлов, %d рёбер CHILD_OF\n", cat.Version, st.Nodes, st.Edges)
	return nil
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

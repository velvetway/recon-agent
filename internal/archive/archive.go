// Package archive выгружает прогон разведки из графа в архив на диске.
//
// Граф — источник правды: архив не хранится параллельно, а собирается из
// наблюдений (:Observation) одного прогона. Раскладка:
//
//	runs/<run_id>/
//	  manifest.json    сведения о прогоне, счётчики, хэши файлов
//	  by-tool/*.jsonl  наблюдения по инструментам (для отладки)
//	  by-asset/*.md    досье на каждый актив (вход для фильтра и LLM)
//	  raw/             сырой вывод инструментов, если был сохранён при скане
//
// by-asset — то, что уходит в LLM: модель рассуждает про один хост, а не
// листает файлы по инструментам.
package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/velvet1way/recon-agent/internal/graph"
)

// Store — часть графа, нужная архиву (позволяет подменять в тестах).
type Store interface {
	Run(ctx context.Context, runID string) (graph.RunInfo, error)
	Observations(ctx context.Context, runID string) ([]graph.Observation, error)
}

// Result — итог экспорта.
type Result struct {
	Dir          string
	Observations int
	Tools        int
	Assets       int
}

// Manifest — содержимое manifest.json.
type Manifest struct {
	RunID        string            `json:"run_id"`
	Program      string            `json:"program"`
	Platform     string            `json:"platform,omitempty"`
	Profile      string            `json:"profile,omitempty"`
	StartedAt    string            `json:"started_at,omitempty"`
	GeneratedAt  string            `json:"generated_at"`
	Observations int               `json:"observations"`
	Tools        map[string]int    `json:"tools"`  // инструмент → число наблюдений
	Assets       []string          `json:"assets"` // отсортированный список активов
	Files        map[string]string `json:"files"`  // относительный путь → sha256
}

// obsLine — одна строка by-tool/*.jsonl.
type obsLine struct {
	ID       string `json:"id"`
	Asset    string `json:"asset"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Evidence string `json:"evidence,omitempty"`
}

// Export собирает архив прогона в root/<runID>. rawSrc — каталог с сырым
// выводом инструментов; если он есть, копируется в raw/. Пустой rawSrc
// пропускается.
func Export(ctx context.Context, store Store, runID, root, rawSrc string) (Result, error) {
	info, err := store.Run(ctx, runID)
	if err != nil {
		return Result{}, err
	}
	obs, err := store.Observations(ctx, runID)
	if err != nil {
		return Result{}, err
	}

	dir := filepath.Join(root, runID)
	for _, sub := range []string{"by-tool", "by-asset"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return Result{}, fmt.Errorf("создание %s: %w", sub, err)
		}
	}

	byTool := map[string][]graph.Observation{}
	byAsset := map[string][]graph.Observation{}
	for _, o := range obs {
		byTool[o.Tool] = append(byTool[o.Tool], o)
		byAsset[o.Asset] = append(byAsset[o.Asset], o)
	}

	files := map[string]string{} // относительный путь → sha256
	toolNames := newNamer()
	assetNames := newNamer()

	// by-tool: по одному JSONL на инструмент.
	for _, tool := range sortedKeys(byTool) {
		list := byTool[tool]
		rel := filepath.Join("by-tool", toolNames.for_(tool)+".jsonl")
		var b strings.Builder
		for _, o := range list {
			line, err := json.Marshal(obsLine{ID: o.ID, Asset: o.Asset, Kind: o.Kind, Value: o.Value, Evidence: o.Evidence})
			if err != nil {
				return Result{}, err
			}
			b.Write(line)
			b.WriteByte('\n')
		}
		if err := writeFile(dir, rel, []byte(b.String()), files); err != nil {
			return Result{}, err
		}
	}

	// by-asset: markdown-досье.
	for _, asset := range sortedKeys(byAsset) {
		rel := filepath.Join("by-asset", assetNames.for_(asset)+".md")
		if err := writeFile(dir, rel, assetDossier(asset, byAsset[asset]), files); err != nil {
			return Result{}, err
		}
	}

	if rawSrc != "" {
		if err := copyRaw(rawSrc, filepath.Join(dir, "raw"), files); err != nil {
			return Result{}, err
		}
	}

	assets := make([]string, 0, len(byAsset))
	for a := range byAsset {
		assets = append(assets, a)
	}
	sort.Strings(assets)
	tools := map[string]int{}
	for t, l := range byTool {
		tools[t] = len(l)
	}

	man := Manifest{
		RunID: info.ID, Program: info.Program, Platform: info.Platform, Profile: info.Profile,
		StartedAt: msToRFC3339(info.StartedAt), GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Observations: len(obs), Tools: tools, Assets: assets, Files: files,
	}
	manBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(manBytes, '\n'), 0o644); err != nil {
		return Result{}, err
	}

	return Result{Dir: dir, Observations: len(obs), Tools: len(tools), Assets: len(assets)}, nil
}

// assetDossier — markdown-досье на один актив: факты, сгруппированные по виду.
func assetDossier(asset string, obs []graph.Observation) []byte {
	byKind := map[string][]graph.Observation{}
	var kinds []string
	for _, o := range obs {
		if _, ok := byKind[o.Kind]; !ok {
			kinds = append(kinds, o.Kind)
		}
		byKind[o.Kind] = append(byKind[o.Kind], o)
	}
	sort.Strings(kinds)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", asset)
	for _, kind := range kinds {
		fmt.Fprintf(&b, "## %s\n\n", kind)
		seen := map[string]bool{}
		for _, o := range byKind[kind] {
			if seen[o.Value] {
				continue
			}
			seen[o.Value] = true
			ev := ""
			if o.Evidence != "" {
				ev = " — " + o.Evidence
			}
			// `id` рядом с фактом: на него ссылаются выводы о CWE (evidence_id).
			fmt.Fprintf(&b, "- `%s` %s%s\n", o.ID, o.Value, ev)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// writeFile пишет файл и запоминает его sha256 в files по относительному пути.
func writeFile(dir, rel string, data []byte, files map[string]string) error {
	if err := os.WriteFile(filepath.Join(dir, rel), data, 0o644); err != nil {
		return fmt.Errorf("запись %s: %w", rel, err)
	}
	sum := sha256.Sum256(data)
	files[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
	return nil
}

// copyRaw копирует дерево rawSrc в dst, записывая хэши файлов в files под
// префиксом raw/.
func copyRaw(rawSrc, dst string, files map[string]string) error {
	st, err := os.Stat(rawSrc)
	if err != nil || !st.IsDir() {
		return nil // нет сырого вывода — не ошибка
	}
	return filepath.WalkDir(rawSrc, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relInner, err := filepath.Rel(rawSrc, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, relInner)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files[filepath.ToSlash(filepath.Join("raw", relInner))] = hex.EncodeToString(sum[:])
		return nil
	})
}

// safeName делает из актива или инструмента безопасное имя файла.
func safeName(s string) string {
	if s == "" {
		return "_"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// namer выдаёт уникальные имена файлов: при коллизии после очистки (разные
// активы дали одно имя) к имени добавляется короткий хэш оригинала.
type namer struct{ used map[string]bool }

func newNamer() *namer { return &namer{used: map[string]bool{}} }

func (n *namer) for_(orig string) string {
	name := safeName(orig)
	if n.used[name] {
		sum := sha256.Sum256([]byte(orig))
		name += "-" + hex.EncodeToString(sum[:3])
	}
	n.used[name] = true
	return name
}

// sortedKeys — отсортированные ключи для детерминированного обхода.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func msToRFC3339(ms int64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/graph"
)

// fakeStore подменяет граф: архив зависит только от Run и Observations.
type fakeStore struct {
	info graph.RunInfo
	obs  []graph.Observation
}

func (f fakeStore) Run(context.Context, string) (graph.RunInfo, error) { return f.info, nil }
func (f fakeStore) Observations(context.Context, string) ([]graph.Observation, error) {
	return f.obs, nil
}

func sampleStore() fakeStore {
	run := "run-20260101-120000"
	obs := func(asset, tool, kind, value, ev string) graph.Observation {
		return graph.Observation{
			ID:    graph.ObservationID(run, asset, tool, kind, value),
			RunID: run, Asset: asset, Tool: tool, Kind: kind, Value: value, Evidence: ev,
		}
	}
	return fakeStore{
		info: graph.RunInfo{ID: run, Program: "Example", Platform: "hackerone", Profile: "light", StartedAt: 1735732800000},
		obs: []graph.Observation{
			obs("api.example.com", "bbot", "subdomain", "api.example.com", "crt"),
			obs("api.example.com", "dns", "dns_a", "203.0.113.5", "resolver"),
			obs("api.example.com", "httpx", "http_service", "https://api.example.com", "200 API"),
			obs("api.example.com", "httpx", "tech", "nginx", "https://api.example.com"),
			obs("203.0.113.5", "nmap", "open_port", "443/tcp", "https"),
		},
	}
}

func TestExportLayout(t *testing.T) {
	root := t.TempDir()
	res, err := Export(context.Background(), sampleStore(), "run-20260101-120000", root, "", Options{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if res.Observations != 5 || res.Assets != 2 || res.Tools != 4 {
		t.Errorf("Result = %+v; want 5 obs, 2 assets, 4 tools", res)
	}
	dir := res.Dir

	// Манифест: поля прогона и хэши совпадают с файлами на диске.
	var man Manifest
	readJSON(t, filepath.Join(dir, "manifest.json"), &man)
	if man.Program != "Example" || man.Profile != "light" || man.Observations != 5 {
		t.Errorf("манифест: %+v", man)
	}
	if man.StartedAt != "2025-01-01T12:00:00Z" {
		t.Errorf("started_at = %q", man.StartedAt)
	}
	if len(man.Files) == 0 {
		t.Fatal("в манифесте нет файлов")
	}
	for rel, want := range man.Files {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("файл из манифеста не читается: %s: %v", rel, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("хэш %s не совпадает", rel)
		}
	}

	// by-tool: nmap.jsonl — одна строка валидного JSON.
	nmap := readFile(t, filepath.Join(dir, "by-tool", "nmap.jsonl"))
	lines := strings.Split(strings.TrimSpace(nmap), "\n")
	if len(lines) != 1 {
		t.Fatalf("nmap.jsonl: %d строк, want 1", len(lines))
	}
	var ol obsLine
	if err := json.Unmarshal([]byte(lines[0]), &ol); err != nil {
		t.Fatalf("строка by-tool не JSON: %v", err)
	}
	if ol.Value != "443/tcp" || ol.Asset != "203.0.113.5" {
		t.Errorf("obsLine = %+v", ol)
	}

	// by-asset: досье хоста содержит секции по видам и evidence-id.
	dossier := readFile(t, filepath.Join(dir, "by-asset", "api.example.com.md"))
	for _, want := range []string{"# api.example.com", "## http_service", "## tech", "nginx", "https://api.example.com"} {
		if !strings.Contains(dossier, want) {
			t.Errorf("в досье нет %q", want)
		}
	}
	id := graph.ObservationID("run-20260101-120000", "api.example.com", "httpx", "tech", "nginx")
	if !strings.Contains(dossier, id) {
		t.Errorf("в досье нет evidence-id %s", id)
	}
}

func TestExportRaw(t *testing.T) {
	rawSrc := t.TempDir()
	os.MkdirAll(filepath.Join(rawSrc, "bbot"), 0o755)
	os.WriteFile(filepath.Join(rawSrc, "bbot", "output.ndjson"), []byte(`{"x":1}`), 0o644)

	root := t.TempDir()
	res, err := Export(context.Background(), sampleStore(), "run-20260101-120000", root, rawSrc, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, filepath.Join(res.Dir, "raw", "bbot", "output.ndjson"))
	if got != `{"x":1}` {
		t.Errorf("сырой файл не скопирован: %q", got)
	}
	var man Manifest
	readJSON(t, filepath.Join(res.Dir, "manifest.json"), &man)
	if _, ok := man.Files["raw/bbot/output.ndjson"]; !ok {
		t.Errorf("raw-файл не попал в манифест: %v", man.Files)
	}
}

// Активы, дающие после очистки одно имя, не перезаписывают друг друга.
func TestExportNameCollision(t *testing.T) {
	run := "r1"
	mk := func(asset string) graph.Observation {
		return graph.Observation{ID: graph.ObservationID(run, asset, "t", "k", asset),
			RunID: run, Asset: asset, Tool: "t", Kind: "k", Value: asset}
	}
	st := fakeStore{
		info: graph.RunInfo{ID: run, Program: "P"},
		obs:  []graph.Observation{mk("a:b"), mk("a/b")}, // оба → "a_b"
	}
	root := t.TempDir()
	res, err := Export(context.Background(), st, run, root, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Assets != 2 {
		t.Fatalf("assets = %d, want 2", res.Assets)
	}
	entries, _ := os.ReadDir(filepath.Join(res.Dir, "by-asset"))
	if len(entries) != 2 {
		t.Errorf("файлов досье = %d, want 2 (коллизия имён потеряла актив)", len(entries))
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(readFile(t, path)), v); err != nil {
		t.Fatalf("json %s: %v", path, err)
	}
}

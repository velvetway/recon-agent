package filter

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/velvet1way/recon-agent/internal/graph"
)

// Config — правила шумового фильтра. Загружается из YAML или берётся Default.
type Config struct {
	// Маркеры парковочных страниц: если значение или evidence наблюдения
	// содержит один из них, актив считается «мёртвым» и отбрасывается.
	ParkingMarkers []string `yaml:"parking_markers"`
	// Маркеры CDN/WAF (по tech/webserver). Актив помечается как за CDN;
	// отбрасывается только при DropCDN.
	CDNMarkers []string `yaml:"cdn_markers"`
	DropCDN    bool     `yaml:"drop_cdn"`
	// Лимиты размера досье, чтобы вход LLM не разрастался. 0 — без лимита.
	MaxPerKind  int `yaml:"max_per_kind"`  // наблюдений одного вида на актив
	MaxPerAsset int `yaml:"max_per_asset"` // всего наблюдений на актив
}

// Default — разумные значения по умолчанию.
func Default() Config {
	return Config{
		ParkingMarkers: []string{
			"domain for sale", "buy this domain", "this domain is for sale",
			"parked", "parking", "domain parking", "coming soon", "under construction",
		},
		CDNMarkers: []string{
			"cloudflare", "akamai", "fastly", "sucuri", "incapsula", "imperva",
			"cloudfront", "stackpath", "azion",
		},
		DropCDN:     false, // за CDN может стоять валидная цель — по умолчанию помечаем, не режем
		MaxPerKind:  50,
		MaxPerAsset: 200,
	}
}

// Load читает конфиг из YAML, недостающие поля берёт из Default.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("чтение конфига фильтра: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("разбор конфига фильтра: %w", err)
	}
	return cfg, nil
}

// Filter применяет правила к наблюдениям.
type Filter struct {
	cfg     Config
	parking []string // маркеры в нижнем регистре
	cdn     []string
}

// New создаёт фильтр из конфига.
func New(cfg Config) *Filter {
	return &Filter{cfg: cfg, parking: lower(cfg.ParkingMarkers), cdn: lower(cfg.CDNMarkers)}
}

// Report — сводка работы фильтра.
type Report struct {
	Input        int
	Kept         int
	Deduped      int
	Capped       int
	DroppedPark  []string // активы-парковки
	CDN          []string // активы за CDN (помечены или отброшены)
	DroppedCDN   []string // активы за CDN, отброшенные при DropCDN
	SecretsFound []string // типы вырезанных секретов (из Sanitize по evidence)
}

// Apply возвращает отфильтрованные наблюдения и сводку. Порядок входа
// сохраняется, чтобы вывод был детерминированным.
func (f *Filter) Apply(obs []graph.Observation) ([]graph.Observation, Report) {
	rep := Report{Input: len(obs)}

	// Сгруппировать по активу, попутно определить парковки и CDN.
	byAsset := map[string][]graph.Observation{}
	var assetOrder []string
	for _, o := range obs {
		if _, ok := byAsset[o.Asset]; !ok {
			assetOrder = append(assetOrder, o.Asset)
		}
		byAsset[o.Asset] = append(byAsset[o.Asset], o)
	}

	parkSet := map[string]bool{}
	cdnSet := map[string]bool{}
	for asset, list := range byAsset {
		for _, o := range list {
			hay := strings.ToLower(o.Value + " " + o.Evidence)
			if containsAny(hay, f.parking) {
				parkSet[asset] = true
			}
			if containsAny(hay, f.cdn) {
				cdnSet[asset] = true
			}
		}
	}

	seen := map[string]bool{}    // asset|kind|value — дедуп
	perKind := map[string]int{}  // asset|kind → счётчик
	perAsset := map[string]int{} // asset → счётчик
	var kept []graph.Observation

	for _, asset := range assetOrder {
		if parkSet[asset] {
			rep.DroppedPark = append(rep.DroppedPark, asset)
			continue
		}
		if cdnSet[asset] {
			rep.CDN = append(rep.CDN, asset)
			if f.cfg.DropCDN {
				rep.DroppedCDN = append(rep.DroppedCDN, asset)
				continue
			}
		}
		for _, o := range byAsset[asset] {
			dk := o.Asset + "|" + o.Kind + "|" + o.Value
			if seen[dk] {
				rep.Deduped++
				continue
			}
			seen[dk] = true
			kk := o.Asset + "|" + o.Kind
			if f.cfg.MaxPerKind > 0 && perKind[kk] >= f.cfg.MaxPerKind {
				rep.Capped++
				continue
			}
			if f.cfg.MaxPerAsset > 0 && perAsset[o.Asset] >= f.cfg.MaxPerAsset {
				rep.Capped++
				continue
			}
			perKind[kk]++
			perAsset[o.Asset]++
			kept = append(kept, o)
		}
	}

	sort.Strings(rep.DroppedPark)
	sort.Strings(rep.CDN)
	sort.Strings(rep.DroppedCDN)
	rep.Kept = len(kept)
	return kept, rep
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

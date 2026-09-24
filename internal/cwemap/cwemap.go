// Package cwemap сопоставляет наблюдения разведки с кандидатами-CWE по
// детерминированному словарю правил (data/rules/*.yaml).
//
// Это базовый слой «сигнал → CWE»: он не утверждает наличие уязвимости, а
// показывает направление для проверки. Каждый кандидат проходит CWE-guard —
// принимается, только если его ID есть в каталоге (internal/cwe), так же как
// scope-guard пропускает лишь цели из скоупа. Позже LLM (фаза 7) расширяет и
// приоритизирует этот список, а не заменяет его.
package cwemap

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/velvet1way/recon-agent/internal/cwe"
	"github.com/velvet1way/recon-agent/internal/graph"
)

// Condition — условие срабатывания правила на одном наблюдении. Пустые поля
// не проверяются; должно быть задано хотя бы одно (проверяется при загрузке).
type Condition struct {
	Tool             string `yaml:"tool"`              // точное совпадение инструмента
	Kind             string `yaml:"kind"`              // точное совпадение вида факта
	ValueContains    string `yaml:"value_contains"`    // подстрока в value (без учёта регистра)
	ValueRegex       string `yaml:"value_regex"`       // регэксп по value
	EvidenceContains string `yaml:"evidence_contains"` // подстрока в evidence
	EvidenceRegex    string `yaml:"evidence_regex"`    // регэксп по evidence
}

// Rule — правило словаря.
type Rule struct {
	ID         string    `yaml:"id"`
	When       Condition `yaml:"when"`
	CWE        string    `yaml:"cwe"`        // ID слабости; проверяется по каталогу
	Confidence float64   `yaml:"confidence"` // 0..1, базовая уверенность эвристики
	Title      string    `yaml:"title"`      // короткое пояснение
	Vector     string    `yaml:"vector"`     // что проверить
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// compiledRule — правило с разобранными регэкспами.
type compiledRule struct {
	Rule
	valueRe *regexp.Regexp
	evidRe  *regexp.Regexp
}

// Finding — кандидат-CWE, найденный по одному наблюдению.
type Finding struct {
	Asset      string
	CWE        string // канонический ID (без префикса), гарантированно из каталога
	CWETitle   string // название из каталога (RU, если есть)
	Confidence float64
	RuleID     string
	Title      string
	Vector     string
	EvidenceID string // id наблюдения — это evidence_id для отчёта
	Signal     string // краткое человекочитаемое значение сигнала
}

// Engine применяет правила к наблюдениям.
type Engine struct {
	rules []compiledRule
	cat   *cwe.Catalog
}

// LoadDir загружает все *.yaml из каталога dir и проверяет их по каталогу CWE.
func LoadDir(dir string, cat *cwe.Catalog) (*Engine, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("в %s нет файлов правил *.yaml", dir)
	}
	var all []Rule
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("чтение %s: %w", p, err)
		}
		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("разбор %s: %w", p, err)
		}
		all = append(all, rf.Rules...)
	}
	return New(all, cat)
}

// New компилирует и проверяет правила. Ошибка возвращается, если правило
// битое: нет ID, пустое условие, кривой регэксп или CWE вне каталога.
func New(rules []Rule, cat *cwe.Catalog) (*Engine, error) {
	e := &Engine{cat: cat}
	seen := map[string]bool{}
	for i, r := range rules {
		if r.ID == "" {
			return nil, fmt.Errorf("правило #%d без id", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("дублирующийся id правила %q", r.ID)
		}
		seen[r.ID] = true

		if r.When.empty() {
			return nil, fmt.Errorf("правило %q: пустое условие when", r.ID)
		}
		// CWE-guard: кандидат обязан существовать в каталоге.
		id, ok := cat.Normalize(r.CWE)
		if !ok {
			return nil, fmt.Errorf("правило %q ссылается на CWE-%s, которого нет в каталоге", r.ID, r.CWE)
		}
		r.CWE = id
		if r.Confidence < 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("правило %q: confidence %v вне [0,1]", r.ID, r.Confidence)
		}

		cr := compiledRule{Rule: r}
		if r.When.ValueRegex != "" {
			re, err := regexp.Compile("(?i)" + r.When.ValueRegex)
			if err != nil {
				return nil, fmt.Errorf("правило %q: value_regex: %w", r.ID, err)
			}
			cr.valueRe = re
		}
		if r.When.EvidenceRegex != "" {
			re, err := regexp.Compile("(?i)" + r.When.EvidenceRegex)
			if err != nil {
				return nil, fmt.Errorf("правило %q: evidence_regex: %w", r.ID, err)
			}
			cr.evidRe = re
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

// Len — число загруженных правил.
func (e *Engine) Len() int { return len(e.rules) }

// Match прогоняет наблюдения через правила и возвращает кандидатов,
// отсортированных детерминированно: по активу, затем по убыванию уверенности.
func (e *Engine) Match(obs []graph.Observation) []Finding {
	var out []Finding
	for _, o := range obs {
		for _, r := range e.rules {
			if !r.matches(o) {
				continue
			}
			w, _ := e.cat.Get(r.CWE) // существование гарантировано CWE-guard
			out = append(out, Finding{
				Asset: o.Asset, CWE: r.CWE, CWETitle: w.Title(),
				Confidence: r.Confidence, RuleID: r.ID, Title: r.Title, Vector: r.Vector,
				EvidenceID: o.ID, Signal: o.Kind + "=" + o.Value,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Asset != out[j].Asset {
			return out[i].Asset < out[j].Asset
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].CWE < out[j].CWE
	})
	return out
}

func (c Condition) empty() bool {
	return c.Tool == "" && c.Kind == "" && c.ValueContains == "" &&
		c.ValueRegex == "" && c.EvidenceContains == "" && c.EvidenceRegex == ""
}

func (r compiledRule) matches(o graph.Observation) bool {
	if r.When.Tool != "" && !strings.EqualFold(r.When.Tool, o.Tool) {
		return false
	}
	if r.When.Kind != "" && !strings.EqualFold(r.When.Kind, o.Kind) {
		return false
	}
	if r.When.ValueContains != "" && !containsFold(o.Value, r.When.ValueContains) {
		return false
	}
	if r.When.EvidenceContains != "" && !containsFold(o.Evidence, r.When.EvidenceContains) {
		return false
	}
	if r.valueRe != nil && !r.valueRe.MatchString(o.Value) {
		return false
	}
	if r.evidRe != nil && !r.evidRe.MatchString(o.Evidence) {
		return false
	}
	return true
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

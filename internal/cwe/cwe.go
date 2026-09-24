// Package cwe — каталог слабостей MITRE CWE (data/cwe/cwe.json).
//
// Каталог нужен в двух местах: как справочник для отчёта и как CWE-guard —
// любой CWE-ID, пришедший от правил или LLM, принимается только если он есть
// в каталоге (так же, как scope-guard пропускает только цели из скоупа).
//
// Файл собирается скриптом tools/cwe/extract.py из официального XML MITRE.
package cwe

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Weakness — одна запись каталога.
type Weakness struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	NameRU        string              `json:"name_ru"`
	Abstraction   string              `json:"abstraction"` // Pillar, Class, Base, Variant, Compound
	Status        string              `json:"status"`
	Top25Rank     int                 `json:"top25_rank"` // 0 — не в Top 25
	Description   string              `json:"description"`
	DescriptionRU string              `json:"description_ru"`
	Extended      string              `json:"extended"`
	Relations     map[string][]string `json:"relations"` // ChildOf, PeerOf, CanPrecede...
	Consequences  []Consequence       `json:"consequences"`
	Likelihood    string              `json:"likelihood"`
	Modes         []string            `json:"modes"`
	Platforms     []Platform          `json:"platforms"`
	Mitigations   []Mitigation        `json:"mitigations"`
	Detection     []Detection         `json:"detection"`
	Observed      []Observed          `json:"observed"`
	CAPEC         []string            `json:"capec"`
	AltNames      []string            `json:"alt_names"`
}

// Consequence — последствие эксплуатации.
type Consequence struct {
	Scope  []string `json:"scope"`
	Impact []string `json:"impact"`
	Note   string   `json:"note"`
}

// Platform — язык, технология или ОС, где встречается слабость.
type Platform struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Prevalence string `json:"prevalence"`
}

// Mitigation — мера защиты.
type Mitigation struct {
	Phases        []string `json:"phases"`
	Strategy      string   `json:"strategy"`
	Text          string   `json:"text"`
	Effectiveness string   `json:"effectiveness"`
}

// Detection — метод обнаружения.
type Detection struct {
	Method        string `json:"method"`
	Text          string `json:"text"`
	Effectiveness string `json:"effectiveness"`
}

// Observed — пример реальной уязвимости (обычно CVE).
type Observed struct {
	Ref  string `json:"ref"`
	Text string `json:"text"`
}

// Title возвращает русское название, а если перевода нет — английское.
func (w *Weakness) Title() string {
	if w.NameRU != "" {
		return w.NameRU
	}
	return w.Name
}

// Parents — родители в иерархии Research Concepts (CWE-1000).
func (w *Weakness) Parents() []string { return w.Relations["ChildOf"] }

// Catalog — загруженный каталог с индексом по ID.
type Catalog struct {
	Version string
	Date    string
	View    string

	list []*Weakness
	byID map[string]*Weakness
}

type catalogFile struct {
	Source     string      `json:"source"`
	Version    string      `json:"version"`
	Date       string      `json:"date"`
	View       string      `json:"view"`
	Weaknesses []*Weakness `json:"weaknesses"`
}

// Load читает каталог из файла.
func Load(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("открытие каталога CWE: %w", err)
	}
	defer f.Close()
	c, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse читает каталог из потока.
func Parse(r io.Reader) (*Catalog, error) {
	var cf catalogFile
	if err := json.NewDecoder(r).Decode(&cf); err != nil {
		return nil, fmt.Errorf("разбор каталога CWE: %w", err)
	}
	if len(cf.Weaknesses) == 0 {
		return nil, fmt.Errorf("каталог CWE пуст")
	}
	c := &Catalog{
		Version: cf.Version,
		Date:    cf.Date,
		View:    cf.View,
		list:    cf.Weaknesses,
		byID:    make(map[string]*Weakness, len(cf.Weaknesses)),
	}
	for _, w := range cf.Weaknesses {
		if w.ID == "" {
			return nil, fmt.Errorf("запись без ID: %q", w.Name)
		}
		if _, dup := c.byID[w.ID]; dup {
			return nil, fmt.Errorf("дублирующийся ID CWE-%s", w.ID)
		}
		c.byID[w.ID] = w
	}
	return c, nil
}

// Len — число записей.
func (c *Catalog) Len() int { return len(c.list) }

// All — все записи по возрастанию ID.
func (c *Catalog) All() []*Weakness { return c.list }

// Normalize приводит "79", "CWE-79", "cwe 79" к каноническому "79" и
// сообщает, есть ли такая запись в каталоге. Это и есть CWE-guard.
func (c *Catalog) Normalize(id string) (string, bool) {
	s := strings.ToUpper(strings.TrimSpace(id))
	s = strings.TrimPrefix(s, "CWE")
	s = strings.TrimLeft(s, "-_ :")
	if s == "" {
		return "", false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	s = strings.TrimLeft(s, "0")
	_, ok := c.byID[s]
	return s, ok
}

// Get возвращает запись по ID в любом формате, который понимает Normalize.
func (c *Catalog) Get(id string) (*Weakness, bool) {
	n, ok := c.Normalize(id)
	if !ok {
		return nil, false
	}
	return c.byID[n], true
}

// Lineage — цепочка основных родителей от столпа (Pillar) к непосредственному
// родителю записи. Для самого столпа пустая.
func (c *Catalog) Lineage(id string) []string {
	w, ok := c.Get(id)
	if !ok {
		return nil
	}
	var chain []string
	seen := map[string]bool{w.ID: true}
	for {
		ps := w.Parents()
		if len(ps) == 0 {
			break
		}
		p, ok := c.byID[ps[0]]
		if !ok || seen[p.ID] {
			break // защита от битых ссылок и циклов
		}
		seen[p.ID] = true
		chain = append([]string{p.ID}, chain...)
		w = p
	}
	return chain
}

package cwe

import (
	"reflect"
	"strings"
	"testing"
)

// Мини-каталог: столп 707 → класс 74 → базовая 79, плюс цикл 1↔2 для
// проверки защиты Lineage.
const fixture = `{
 "version":"4.14","date":"2024-02-29","view":"1000",
 "weaknesses":[
  {"id":"1","name":"Loop A","abstraction":"Base","relations":{"ChildOf":["2"]}},
  {"id":"2","name":"Loop B","abstraction":"Base","relations":{"ChildOf":["1"]}},
  {"id":"74","name":"Injection","name_ru":"Инъекция","abstraction":"Class","relations":{"ChildOf":["707"]}},
  {"id":"79","name":"XSS","name_ru":"Межсайтовый скриптинг","abstraction":"Base","top25_rank":2,
   "relations":{"ChildOf":["74"],"PeerOf":["352"]},"capec":["63"]},
  {"id":"707","name":"Improper Neutralization","abstraction":"Pillar","relations":{}}
 ]}`

func testCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := Parse(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c
}

func TestNormalize(t *testing.T) {
	c := testCatalog(t)
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"79", "79", true},
		{"CWE-79", "79", true},
		{"cwe-79", "79", true},
		{" CWE 79 ", "79", true},
		{"CWE-079", "79", true},       // ведущие нули
		{"CWE-99999", "99999", false}, // формат верный, но записи нет
		{"CWE-79a", "", false},
		{"XSS", "", false},
		{"", "", false},
		{"CWE-", "", false},
	}
	for _, tc := range cases {
		got, ok := c.Normalize(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Normalize(%q) = %q,%v; want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestGetAndTitle(t *testing.T) {
	c := testCatalog(t)
	w, ok := c.Get("CWE-79")
	if !ok || w.Name != "XSS" || w.Top25Rank != 2 {
		t.Fatalf("Get(CWE-79) = %+v, %v", w, ok)
	}
	if w.Title() != "Межсайтовый скриптинг" {
		t.Errorf("Title с переводом = %q", w.Title())
	}
	p, _ := c.Get("707")
	if p.Title() != "Improper Neutralization" {
		t.Errorf("Title без перевода = %q", p.Title())
	}
	if _, ok := c.Get("352"); ok {
		t.Error("Get(352) нашёл запись, которой нет в каталоге")
	}
}

func TestLineage(t *testing.T) {
	c := testCatalog(t)
	if got := c.Lineage("79"); !reflect.DeepEqual(got, []string{"707", "74"}) {
		t.Errorf("Lineage(79) = %v", got)
	}
	if got := c.Lineage("707"); len(got) != 0 {
		t.Errorf("Lineage(столп) = %v, want пусто", got)
	}
	if got := c.Lineage("1"); len(got) != 1 || got[0] != "2" {
		t.Errorf("Lineage на цикле = %v, want [2]", got)
	}
	if got := c.Lineage("404"); got != nil {
		t.Errorf("Lineage(нет в каталоге) = %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"пустой":  `{"weaknesses":[]}`,
		"без ID":  `{"weaknesses":[{"name":"x"}]}`,
		"дубль":   `{"weaknesses":[{"id":"1"},{"id":"1"}]}`,
		"не JSON": `{`,
	}
	for name, in := range cases {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// Проверка реального каталога из репозитория: он должен грузиться, быть
// полным и содержать перевод.
func TestRealCatalog(t *testing.T) {
	c, err := Load("../../data/cwe/cwe.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Len() < 900 {
		t.Errorf("в каталоге %d записей, ожидалось не меньше 900", c.Len())
	}
	pillars, top25 := 0, 0
	for _, w := range c.All() {
		if w.Abstraction == "Pillar" {
			pillars++
		}
		if w.Top25Rank > 0 {
			top25++
		}
		if w.NameRU == "" || w.DescriptionRU == "" {
			t.Errorf("CWE-%s без перевода", w.ID)
		}
		for _, p := range w.Parents() {
			if _, ok := c.Get(p); !ok {
				t.Errorf("CWE-%s ссылается на отсутствующего родителя CWE-%s", w.ID, p)
			}
		}
	}
	if pillars != 10 {
		t.Errorf("столпов %d, ожидалось 10", pillars)
	}
	if top25 != 25 {
		t.Errorf("записей Top 25: %d, ожидалось 25", top25)
	}
	if got := c.Lineage("79"); !reflect.DeepEqual(got, []string{"707", "74"}) {
		t.Errorf("Lineage(79) = %v", got)
	}
}

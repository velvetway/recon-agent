package cwemap

import (
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/cwe"
	"github.com/velvet1way/recon-agent/internal/graph"
)

// Мини-каталог с ID, на которые ссылаются тесты и реальный словарь правил.
const catFixture = `{"version":"4.14","weaknesses":[
  {"id":"200","name":"Information Exposure","name_ru":"Раскрытие информации","abstraction":"Class","relations":{}},
  {"id":"284","name":"Improper Access Control","abstraction":"Pillar","relations":{}},
  {"id":"306","name":"Missing Authentication","name_ru":"Отсутствие аутентификации","abstraction":"Base","relations":{}},
  {"id":"319","name":"Cleartext Transmission","name_ru":"Передача открытым текстом","abstraction":"Base","relations":{}},
  {"id":"1395","name":"Vulnerable Third-Party Component","abstraction":"Base","relations":{}}
]}`

func testCat(t *testing.T) *cwe.Catalog {
	t.Helper()
	c, err := cwe.Parse(strings.NewReader(catFixture))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func obs(asset, tool, kind, value, ev string) graph.Observation {
	return graph.Observation{
		ID:    graph.ObservationID("r", asset, tool, kind, value),
		RunID: "r", Asset: asset, Tool: tool, Kind: kind, Value: value, Evidence: ev,
	}
}

func TestMatchBasic(t *testing.T) {
	cat := testCat(t)
	e, err := New([]Rule{
		{ID: "ftp", When: Condition{Kind: "open_port", EvidenceContains: "ftp"}, CWE: "CWE-319", Confidence: 0.3, Vector: "check ftp"},
		{ID: "db", When: Condition{Kind: "open_port", EvidenceRegex: "mysql|redis"}, CWE: "306", Confidence: 0.4},
		{ID: "http", When: Condition{Kind: "http_service", ValueRegex: "^http://"}, CWE: "319", Confidence: 0.2},
	}, cat)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	in := []graph.Observation{
		obs("h1", "nmap", "open_port", "21/tcp", "ftp"),
		obs("h1", "nmap", "open_port", "3306/tcp", "mysql"),
		obs("h1", "nmap", "open_port", "443/tcp", "https"), // не сработает
		obs("h2", "httpx", "http_service", "http://h2", "200"),
		obs("h2", "httpx", "http_service", "https://h2", "200"), // не сработает
	}
	got := e.Match(in)
	if len(got) != 3 {
		t.Fatalf("findings = %d, want 3: %+v", len(got), got)
	}
	// Сортировка: h1 раньше h2, внутри h1 — по убыванию confidence (db 0.4 > ftp 0.3).
	if got[0].Asset != "h1" || got[0].RuleID != "db" || got[0].CWE != "306" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].RuleID != "ftp" || got[1].CWETitle != "Передача открытым текстом" {
		t.Errorf("second = %+v", got[1])
	}
	if got[2].Asset != "h2" || got[2].EvidenceID != in[3].ID {
		t.Errorf("third = %+v, evidence должен ссылаться на наблюдение", got[2])
	}
}

func TestCWEGuardRejectsUnknown(t *testing.T) {
	_, err := New([]Rule{{ID: "x", When: Condition{Kind: "tech"}, CWE: "99999"}}, testCat(t))
	if err == nil || !strings.Contains(err.Error(), "99999") {
		t.Errorf("ожидалась ошибка CWE-guard, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	cat := testCat(t)
	cases := map[string]Rule{
		"без id":         {When: Condition{Kind: "tech"}, CWE: "200"},
		"пустое условие": {ID: "a", CWE: "200"},
		"кривой регэксп": {ID: "b", When: Condition{ValueRegex: "("}, CWE: "200"},
		"confidence>1":   {ID: "c", When: Condition{Kind: "tech"}, CWE: "200", Confidence: 1.5},
	}
	for name, r := range cases {
		if _, err := New([]Rule{r}, cat); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
	// Дубль id.
	if _, err := New([]Rule{
		{ID: "d", When: Condition{Kind: "tech"}, CWE: "200"},
		{ID: "d", When: Condition{Kind: "tech"}, CWE: "200"},
	}, cat); err == nil {
		t.Error("дубль id: ожидалась ошибка")
	}
}

func TestCWENormalizedInFinding(t *testing.T) {
	cat := testCat(t)
	e, _ := New([]Rule{{ID: "a", When: Condition{Kind: "tech", ValueContains: "wordpress"}, CWE: "CWE-1395", Confidence: 0.25}}, cat)
	got := e.Match([]graph.Observation{obs("h", "httpx", "tech", "WordPress", "x")})
	if len(got) != 1 || got[0].CWE != "1395" {
		t.Fatalf("CWE в finding должен быть каноническим '1395': %+v", got)
	}
}

// Находки nuclei (kind=finding_cwe) проходят напрямую через CWE-guard,
// минуя правила, с высокой уверенностью.
func TestNativeCWEPassthrough(t *testing.T) {
	cat := testCat(t)
	e, _ := New([]Rule{{ID: "unused", When: Condition{Kind: "tech"}, CWE: "200"}}, cat)
	in := []graph.Observation{
		obs("h", "nuclei", "finding_cwe", "CWE-319", "cve-template | high"),
		obs("h", "nuclei", "finding_cwe", "CWE-99999", "не в каталоге"), // отсекается CWE-guard
	}
	got := e.Match(in)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (несуществующий CWE должен отсеяться): %+v", len(got), got)
	}
	if got[0].CWE != "319" || got[0].RuleID != "nuclei" || got[0].Confidence != nativeCWEConfidence {
		t.Errorf("finding = %+v", got[0])
	}
	if !strings.Contains(got[0].Vector, "nuclei") {
		t.Errorf("вектор должен упоминать nuclei: %q", got[0].Vector)
	}
}

// Настоящий словарь правил должен грузиться и проходить CWE-guard по
// настоящему каталогу — защита от опечаток в ID.
func TestRealRulesAgainstCatalog(t *testing.T) {
	cat, err := cwe.Load("../../data/cwe/cwe.json")
	if err != nil {
		t.Fatalf("Load каталога: %v", err)
	}
	e, err := LoadDir("../../data/rules", cat)
	if err != nil {
		t.Fatalf("LoadDir правил: %v", err)
	}
	if e.Len() < 5 {
		t.Errorf("правил загружено %d, ожидалось не меньше 5", e.Len())
	}
	// Реалистичный набор сигналов даёт кандидатов.
	in := []graph.Observation{
		obs("db.example.com", "nmap", "open_port", "3306/tcp", "mysql"),
		obs("www.example.com", "httpx", "tech", "WordPress", "https://www.example.com"),
		obs("www.example.com", "httpx", "webserver", "nginx/1.18.0", "x"),
	}
	got := e.Match(in)
	if len(got) < 3 {
		t.Errorf("на реальных правилах кандидатов %d: %+v", len(got), got)
	}
	for _, f := range got {
		if _, ok := cat.Get(f.CWE); !ok {
			t.Errorf("finding ссылается на CWE вне каталога: %s", f.CWE)
		}
		if f.Vector == "" {
			t.Errorf("правило %s без вектора проверки", f.RuleID)
		}
	}
}

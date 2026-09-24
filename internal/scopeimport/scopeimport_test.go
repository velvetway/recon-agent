package scopeimport

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/scope"
)

// Типичный скоуп, скопированный со страницы программы: заголовки,
// маркеры списка, описания, URL, порты, повторы и мусор.
const sample = `
# Скоуп программы Example
In scope:
- *.example.com
- example.com
- https://api.example.com/v2/docs   (публичный API)
- app.example.com:8443 - Production
- admin.example.com, shop.example.com; pay.example.com
203.0.113.0/24
198.51.100.7
2001:db8::1
EXAMPLE.COM
не домен вообще
http://
Out of scope:
- blog.example.com
- status.example.com
203.0.113.128/25
!partner.example.org
Вне скоупа: legacy.example.com
`

func TestParseSample(t *testing.T) {
	rep, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	wantIn := []string{
		"*.example.com", "example.com", "api.example.com", "app.example.com",
		"admin.example.com", "shop.example.com", "pay.example.com",
		"203.0.113.0/24", "198.51.100.7/32", "2001:db8::1/128",
	}
	if got := values(rep.In); !reflect.DeepEqual(got, wantIn) {
		t.Errorf("In:\n got %v\nwant %v", got, wantIn)
	}

	wantOut := []string{
		"blog.example.com", "status.example.com", "203.0.113.128/25",
		"partner.example.org", "legacy.example.com",
	}
	if got := values(rep.Out); !reflect.DeepEqual(got, wantOut) {
		t.Errorf("Out:\n got %v\nwant %v", got, wantOut)
	}

	// "EXAMPLE.COM" — повтор example.com после приведения регистра.
	if rep.Dups != 1 {
		t.Errorf("Dups = %d, want 1", rep.Dups)
	}
	if len(rep.Skipped) != 2 {
		t.Errorf("Skipped = %+v, want 2 строки (текст и пустой URL)", rep.Skipped)
	}
	for _, s := range rep.Skipped {
		if s.Reason == "" || s.Line == 0 {
			t.Errorf("отброшенная строка без причины или номера: %+v", s)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want string
		kind Kind
		ok   bool
	}{
		{"example.com", "example.com", KindDomain, true},
		{"Example.COM.", "example.com", KindDomain, true},
		{"*.example.com", "*.example.com", KindWildcard, true},
		{"https://a.example.com:8443/x?y=1", "a.example.com", KindDomain, true},
		{"http://203.0.113.5:8080/", "203.0.113.5/32", KindIP, true},
		{"a.example.com/path", "a.example.com", KindDomain, true},
		{"10.0.0.7/8", "10.0.0.0/8", KindCIDR, true}, // хост-биты обнуляются
		{"localhost", "", 0, false},                  // без точки — не домен
		{"*.", "", 0, false},
		{"-bad.example.com", "", 0, false},
		{"exa_mple.com", "", 0, false},
	}
	for _, tc := range cases {
		e, reason := classify(tc.in)
		if ok := reason == ""; ok != tc.ok {
			t.Errorf("classify(%q): ok=%v (%s), want %v", tc.in, ok, reason, tc.ok)
			continue
		}
		if tc.ok && (e.Value != tc.want || e.Kind != tc.kind) {
			t.Errorf("classify(%q) = %q/%v, want %q/%v", tc.in, e.Value, e.Kind, tc.want, tc.kind)
		}
	}
}

// Цель в обоих списках остаётся только во "вне скоупа".
func TestInAndOutConflict(t *testing.T) {
	rep, err := Parse(strings.NewReader("a.example.com\nb.example.com\n!a.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := values(rep.In); !reflect.DeepEqual(got, []string{"b.example.com"}) {
		t.Errorf("In = %v", got)
	}
	if got := values(rep.Out); !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Errorf("Out = %v", got)
	}
}

func TestHeaderSwitchesBack(t *testing.T) {
	rep, err := Parse(strings.NewReader("out of scope:\nx.example.com\nin scope:\ny.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.In) != 1 || rep.In[0].Value != "y.example.com" || len(rep.Out) != 1 || rep.Out[0].Value != "x.example.com" {
		t.Errorf("In=%v Out=%v", values(rep.In), values(rep.Out))
	}
}

func TestScopeBuild(t *testing.T) {
	rep, err := Parse(strings.NewReader("b.example.com\n*.example.com\n203.0.113.0/24\n!c.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Scope("Example", "hackerone")
	if s.Program != "Example" || s.Platform != "hackerone" {
		t.Errorf("program/platform = %q/%q", s.Program, s.Platform)
	}
	if !reflect.DeepEqual(s.InScope.Domains, []string{"*.example.com", "b.example.com"}) {
		t.Errorf("InScope.Domains = %v (ожидалась сортировка)", s.InScope.Domains)
	}
	if !s.InScope.Wildcards {
		t.Error("есть wildcard, а Wildcards = false")
	}
	if !reflect.DeepEqual(s.InScope.CIDRs, []string{"203.0.113.0/24"}) {
		t.Errorf("InScope.CIDRs = %v", s.InScope.CIDRs)
	}
	if !reflect.DeepEqual(s.OutOfScope.Domains, []string{"c.example.com"}) {
		t.Errorf("OutOfScope.Domains = %v", s.OutOfScope.Domains)
	}
	if s.RateLimits.GlobalRPS == 0 || s.RateLimits.PerTargetRPS == 0 || s.RateLimits.MaxConcurrent == 0 {
		t.Errorf("rate limits не заполнены: %+v", s.RateLimits)
	}
}

// Сквозная проверка: текст → YAML → config.LoadScope → scope-guard.
// Итоговый файл должен читаться агентом и давать ожидаемые решения.
func TestRoundTripThroughGuard(t *testing.T) {
	rep, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderYAML(rep.Scope("Example", "bugcrowd"), "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	sc, err := config.LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope не принял собранный файл: %v\n%s", err, out)
	}
	g, err := scope.New(sc)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	cases := map[string]bool{
		"example.com":          true,
		"deep.api.example.com": true,  // wildcard
		"blog.example.com":     false, // out_of_scope
		"legacy.example.com":   false, // из строки "Вне скоупа: ..."
		"partner.example.org":  false,
		"203.0.113.10":         true,
		"203.0.113.200":        false, // out /25 перекрывает in /24
		"198.51.100.7":         true,
		"198.51.100.8":         false, // был указан один IP, не сеть
		"evil.com":             false,
	}
	for target, want := range cases {
		if got := g.Allowed(target); got != want {
			t.Errorf("guard.Allowed(%q) = %v, want %v", target, got, want)
		}
	}
	if !strings.HasPrefix(string(out), "# Scope-конфиг") {
		t.Errorf("нет шапки в YAML:\n%s", out)
	}
}

func TestSummary(t *testing.T) {
	rep, err := Parse(strings.NewReader("a.example.com\n!b.example.com\nмусор\na.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Summary()
	for _, want := range []string{"В скоупе: 1", "Вне скоупа: 1", "Отброшено: 1", "строка 3", "Повторов убрано: 1"} {
		if !strings.Contains(s, want) {
			t.Errorf("в сводке нет %q:\n%s", want, s)
		}
	}
}

func values(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Value
	}
	return out
}

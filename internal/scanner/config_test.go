package scanner

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseHeaders(t *testing.T) {
	got, err := ParseHeaders([]string{
		"X-BugBounty: 4fb6f3d2-7387",
		"  User-Agent:  recon/1.0  ",
		"",                        // пропускается
		"x-bugbounty: overridden", // тот же заголовок без учёта регистра → перезапись
	})
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	want := []Header{
		{Name: "x-bugbounty", Value: "overridden"},
		{Name: "User-Agent", Value: "recon/1.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseHeadersErrors(t *testing.T) {
	for _, bad := range []string{"нет двоеточия", ": пустое имя"} {
		if _, err := ParseHeaders([]string{bad}); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
}

func TestNamesHidesValues(t *testing.T) {
	cfg := Config{HTTPHeaders: []Header{{"X-BugBounty", "secret-value"}}}
	names := cfg.Names()
	if !reflect.DeepEqual(names, []string{"X-BugBounty"}) {
		t.Errorf("Names = %v", names)
	}
	if strings.Contains(strings.Join(names, " "), "secret-value") {
		t.Error("Names не должен возвращать значения заголовков")
	}
}

func TestHTTPXArgs(t *testing.T) {
	cfg := Config{
		HTTPHeaders:  []Header{{"X-BugBounty", "abc"}, {"User-Agent", "recon"}},
		PerTargetRPS: 10,
	}
	args := httpxArgs("https://pik.example.ru", cfg)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-H X-BugBounty: abc") {
		t.Errorf("нет заголовка X-BugBounty в аргументах: %v", args)
	}
	if !strings.Contains(joined, "-H User-Agent: recon") {
		t.Errorf("нет второго заголовка: %v", args)
	}
	if !strings.Contains(joined, "-rl 10") {
		t.Errorf("нет лимита скорости: %v", args)
	}
	// -H идёт как две части: флаг и "Имя: значение".
	if !hasPair(args, "-H", "X-BugBounty: abc") {
		t.Errorf("-H и значение должны идти отдельными аргументами: %v", args)
	}
}

func TestHTTPXArgsNoConfig(t *testing.T) {
	args := httpxArgs("h", Config{})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-H ") || strings.Contains(joined, "-rl") {
		t.Errorf("без конфига не должно быть -H и -rl: %v", args)
	}
}

func TestNmapArgs(t *testing.T) {
	args := nmapArgs("203.0.113.5", Config{PerTargetRPS: 10})
	if !hasPair(args, "--max-rate", "10") {
		t.Errorf("нет --max-rate: %v", args)
	}
	if args[len(args)-1] != "203.0.113.5" {
		t.Errorf("IP должен быть последним аргументом: %v", args)
	}
	// Без лимита --max-rate не добавляется.
	if strings.Contains(strings.Join(nmapArgs("ip", Config{}), " "), "--max-rate") {
		t.Error("без лимита --max-rate не нужен")
	}
}

func hasPair(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

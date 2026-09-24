// Package scopeimport разбирает скоуп программы, вставленный текстом или
// файлом, в структуру config.Scope. Формат вольный: то, что обычно копируют
// со страницы bug bounty — по одной цели в строке.
//
// Понимает:
//
//	example.com              корневой домен
//	*.example.com            wildcard (все поддомены)
//	https://api.example.com  URL — берётся только хост
//	app.example.com:8443     хост с портом — порт отбрасывается
//	203.0.113.0/24           CIDR
//	203.0.113.5              одиночный IP → /32 (или /128 для IPv6)
//
// Вне скоупа помечается префиксом "!" в строке или заголовком секции
// ("out of scope:", "вне скоупа:"). Пустые строки, комментарии (#, //) и
// markdown-маркеры списка ("- ", "* ") игнорируются или снимаются.
package scopeimport

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/velvet1way/recon-agent/internal/config"
)

// Kind — тип разобранной цели.
type Kind int

const (
	KindDomain Kind = iota
	KindWildcard
	KindIP
	KindCIDR
)

func (k Kind) String() string {
	switch k {
	case KindDomain:
		return "домен"
	case KindWildcard:
		return "wildcard"
	case KindIP:
		return "IP"
	case KindCIDR:
		return "CIDR"
	}
	return "?"
}

// Entry — одна разобранная цель.
type Entry struct {
	Raw   string // исходный текст строки
	Value string // нормализованное значение (домен или CIDR)
	Kind  Kind
	Line  int
}

// Skip — строка, которую не удалось разобрать.
type Skip struct {
	Line   int
	Raw    string
	Reason string
}

// Report — итог разбора: что попало в скоуп, что вне, что отброшено.
type Report struct {
	In      []Entry
	Out     []Entry
	Skipped []Skip
	Dups    int
}

// заголовки секций переключают режим in/out для последующих строк.
var outHeaders = []string{"out of scope", "out-of-scope", "out_of_scope", "вне скоупа", "не в скоупе"}
var inHeaders = []string{"in scope", "in-scope", "in_scope", "в скоупе"}

// Parse разбирает скоуп из потока.
func Parse(r io.Reader) (*Report, error) {
	rep := &Report{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	seen := make(map[string]bool) // value|out — дедуп
	sectionOut := false
	line := 0

	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "//") {
			continue
		}
		if h, rest, ok := matchHeader(raw); ok {
			sectionOut = h
			if rest == "" {
				continue
			}
			raw = rest // "Out of scope: blog.example.com" — цели в той же строке
		}

		// Строка может содержать несколько целей через запятую или ";".
		for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
			text, out := strings.TrimSpace(item), sectionOut

			// Снять markdown-маркер списка ("- ", "* ", "• "), не тронув wildcard "*.".
			for _, b := range []string{"- ", "* ", "• "} {
				if strings.HasPrefix(text, b) {
					text = strings.TrimSpace(text[len(b):])
					break
				}
			}
			// Явный маркер исключения "!".
			if strings.HasPrefix(text, "!") {
				out = true
				text = strings.TrimSpace(text[1:])
			}
			// Описание после цели ("api.example.com - Production API") отбрасываем.
			if f := strings.Fields(text); len(f) > 0 {
				text = f[0]
			} else {
				continue
			}

			e, reason := classify(text)
			if reason != "" {
				rep.Skipped = append(rep.Skipped, Skip{Line: line, Raw: strings.TrimSpace(item), Reason: reason})
				continue
			}
			e.Raw, e.Line = raw, line

			key := e.Value + "|" + boolStr(out)
			if seen[key] {
				rep.Dups++
				continue
			}
			seen[key] = true
			if out {
				rep.Out = append(rep.Out, e)
			} else {
				rep.In = append(rep.In, e)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("чтение скоупа: %w", err)
	}

	// Цель, попавшая и в in, и в out, остаётся только в out: out_of_scope
	// имеет приоритет, держать её в in_scope незачем.
	outVals := make(map[string]bool, len(rep.Out))
	for _, e := range rep.Out {
		outVals[e.Value] = true
	}
	kept := rep.In[:0]
	for _, e := range rep.In {
		if outVals[e.Value] {
			rep.Dups++
			continue
		}
		kept = append(kept, e)
	}
	rep.In = kept
	return rep, nil
}

// matchHeader распознаёт заголовок секции. Возвращает режим (out) и остаток
// строки после двоеточия, если цели записаны в той же строке.
func matchHeader(s string) (out bool, rest string, ok bool) {
	head, rest := s, ""
	if i := strings.IndexByte(s, ':'); i >= 0 {
		head, rest = s[:i], strings.TrimSpace(s[i+1:])
	}
	l := strings.ToLower(strings.TrimSpace(head))
	for _, h := range outHeaders {
		if l == h {
			return true, rest, true
		}
	}
	for _, h := range inHeaders {
		if l == h {
			return false, rest, true
		}
	}
	return false, "", false
}

// classify нормализует один токен в Entry либо возвращает причину отбраковки.
func classify(tok string) (Entry, string) {
	// CIDR — до одиночного IP, у обоих есть '/'.
	if _, ipnet, err := net.ParseCIDR(tok); err == nil {
		return Entry{Value: ipnet.String(), Kind: KindCIDR}, ""
	}
	if ip := net.ParseIP(tok); ip != nil {
		return Entry{Value: ipCIDR(ip), Kind: KindIP}, ""
	}

	host := hostFromToken(tok)
	if host == "" {
		return Entry{}, "не удалось извлечь хост"
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// Хост мог оказаться IP (например, из URL http://203.0.113.5:8080).
	if ip := net.ParseIP(host); ip != nil {
		return Entry{Value: ipCIDR(ip), Kind: KindIP}, ""
	}

	if strings.HasPrefix(host, "*.") {
		base := host[2:]
		if !validDomain(base) {
			return Entry{}, "некорректный wildcard-домен"
		}
		return Entry{Value: host, Kind: KindWildcard}, ""
	}
	if !validDomain(host) {
		return Entry{}, "не похоже на домен, IP или CIDR"
	}
	return Entry{Value: host, Kind: KindDomain}, ""
}

// hostFromToken вытаскивает хост из URL, из "host/path" и из "host:port".
func hostFromToken(tok string) string {
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		return u.Hostname()
	}
	// Путь после первого слэша.
	if i := strings.IndexByte(tok, '/'); i >= 0 {
		tok = tok[:i]
	}
	// Порт: host:port, но не IPv6 (у него много двоеточий, и он ушёл бы в
	// ParseIP выше; сюда попадает только "домен:порт").
	if strings.Count(tok, ":") == 1 {
		if h, _, err := net.SplitHostPort(tok); err == nil {
			tok = h
		}
	}
	return tok
}

func ipCIDR(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

// validDomain — нестрогая проверка доменного имени: минимум одна точка,
// метки из [a-z0-9-], не начинаются и не кончаются дефисом.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Scope строит config.Scope из отчёта. program и platform задаёт вызывающий.
// Ставит разумные значения rate limits, чтобы записанный файл был полным.
func (rep *Report) Scope(program, platform string) *config.Scope {
	s := &config.Scope{Program: program, Platform: platform}
	fill := func(entries []Entry) (domains, cidrs []string, hasWildcard bool) {
		for _, e := range entries {
			switch e.Kind {
			case KindDomain, KindWildcard:
				domains = append(domains, e.Value)
				if e.Kind == KindWildcard {
					hasWildcard = true
				}
			case KindIP, KindCIDR:
				cidrs = append(cidrs, e.Value)
			}
		}
		sort.Strings(domains)
		sort.Strings(cidrs)
		return
	}
	s.InScope.Domains, s.InScope.CIDRs, s.InScope.Wildcards = fill(rep.In)
	s.OutOfScope.Domains, s.OutOfScope.CIDRs, _ = fill(rep.Out)
	s.RateLimits = config.RateLimits{GlobalRPS: 20, PerTargetRPS: 5, MaxConcurrent: 4}
	return s
}

// RenderYAML сериализует скоуп в формат configs/scope.yaml с поясняющей шапкой.
func RenderYAML(s *config.Scope, source string) ([]byte, error) {
	body, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("сериализация скоупа: %w", err)
	}
	head := "# Scope-конфиг, собран командой agent -scope-import из " + source + ".\n" +
		"# Проверьте списки перед запуском: out_of_scope имеет приоритет над in_scope.\n"
	return append([]byte(head), body...), nil
}

// Summary — человекочитаемая сводка разбора для показа перед записью.
func (rep *Report) Summary() string {
	var b strings.Builder
	section := func(title string, es []Entry) {
		fmt.Fprintf(&b, "%s: %d\n", title, len(es))
		for _, e := range es {
			fmt.Fprintf(&b, "  %-9s %s\n", e.Kind, e.Value)
		}
	}
	section("В скоупе", rep.In)
	section("Вне скоупа", rep.Out)
	if len(rep.Skipped) > 0 {
		fmt.Fprintf(&b, "Отброшено: %d\n", len(rep.Skipped))
		for _, s := range rep.Skipped {
			fmt.Fprintf(&b, "  строка %d: %q — %s\n", s.Line, s.Raw, s.Reason)
		}
	}
	if rep.Dups > 0 {
		fmt.Fprintf(&b, "Повторов убрано: %d\n", rep.Dups)
	}
	return b.String()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

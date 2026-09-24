package scanner

import (
	"fmt"
	"strings"
)

// Config — настройки запуска инструментов: заголовки и лимит скорости.
type Config struct {
	// HTTPHeaders добавляются к каждому HTTP-запросу (httpx и будущие
	// HTTP-инструменты). Многие программы требуют обязательный заголовок,
	// без которого запросы считаются несанкционированными.
	HTTPHeaders []Header
	// PerTargetRPS — потолок запросов в секунду к одному узлу; спускается в
	// сами инструменты (httpx -rl, nmap --max-rate). 0 — без ограничения.
	PerTargetRPS int
}

// Header — один HTTP-заголовок.
type Header struct {
	Name  string
	Value string
}

// String возвращает заголовок в формате "Имя: значение" для передачи в CLI.
func (h Header) String() string { return h.Name + ": " + h.Value }

// ParseHeaders разбирает строки "Имя: значение" в заголовки. Пустые строки
// пропускаются; при более позднем совпадении имени (без учёта регистра)
// значение перезаписывается — так env переопределяет заголовки из конфига.
// Строка без двоеточия или с пустым именем — ошибка.
func ParseHeaders(lines []string) ([]Header, error) {
	byName := map[string]int{} // нижний регистр имени → индекс в out
	var out []Header
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		i := strings.IndexByte(ln, ':')
		if i <= 0 {
			return nil, fmt.Errorf("заголовок %q: ожидается формат \"Имя: значение\"", ln)
		}
		name := strings.TrimSpace(ln[:i])
		val := strings.TrimSpace(ln[i+1:])
		if name == "" {
			return nil, fmt.Errorf("заголовок %q: пустое имя", ln)
		}
		key := strings.ToLower(name)
		if idx, ok := byName[key]; ok {
			out[idx] = Header{Name: name, Value: val}
			continue
		}
		byName[key] = len(out)
		out = append(out, Header{Name: name, Value: val})
	}
	return out, nil
}

// Names возвращает имена заголовков (без значений) — для логов, чтобы не
// светить секреты.
func (c Config) Names() []string {
	names := make([]string, len(c.HTTPHeaders))
	for i, h := range c.HTTPHeaders {
		names[i] = h.Name
	}
	return names
}

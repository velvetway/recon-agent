// Package filter чистит наблюдения перед внешней отправкой: вырезает
// секреты (санитайзер) и отсекает шум по правилам (дедуп, парковки, CDN,
// лимит размера досье).
package filter

import "regexp"

// redaction — правило вырезания секрета: имя типа и шаблон.
type redaction struct {
	name string
	re   *regexp.Regexp
}

// Порядок важен: более специфичные шаблоны раньше общих. Каждый заменяет
// найденное на ‹REDACTED:name›, чтобы факт наличия секрета остался виден,
// а значение — нет.
var redactions = []redaction{
	{"private_key", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"aws_key", regexp.MustCompile(`A(?:KIA|SIA|ROA|IDA)[0-9A-Z]{16}`)},
	{"github_token", regexp.MustCompile(`gh[opusr]_[A-Za-z0-9]{36,}`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"google_key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"bearer", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}=*`)},
	{"basic_auth", regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/]{16,}=*`)},
	// key=value с чувствительным именем: api_key, token, secret, password...
	{"secret_kv", regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|pwd)\b\s*[=:]\s*["']?[^\s"'&]{6,}`)},
	// URL с учётными данными: scheme://user:pass@host
	{"url_creds", regexp.MustCompile(`([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s:/@]+@`)},
}

// Sanitize вырезает из текста узнанные секреты. Возвращает очищенный текст и
// список типов найденных секретов (для отчёта; сами значения не возвращаются).
func Sanitize(s string) (string, []string) {
	var hits []string
	for _, r := range redactions {
		if !r.re.MatchString(s) {
			continue
		}
		hits = append(hits, r.name)
		repl := "‹REDACTED:" + r.name + "›"
		if r.name == "url_creds" {
			// Сохраняем схему и хост, прячем только user:pass@.
			s = r.re.ReplaceAllString(s, "${1}‹REDACTED:url_creds›@")
		} else {
			s = r.re.ReplaceAllString(s, repl)
		}
	}
	return s, hits
}

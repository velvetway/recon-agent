package queue

import "github.com/velvet1way/recon-agent/internal/config"

// Виды задач разведки. Строки — стабильные ключи, на них завязаны диспетчер
// исполнителя и профильные ограничения ниже.
const (
	KindSubdomainEnum = "subdomain_enum" // BBOT, пассивный сбор поддоменов
	KindDNSResolve    = "dns_resolve"    // резолв имени в IP штатным резолвером
	KindHTTPProbe     = "http_probe"     // httpx: живой HTTP-сервис, tech, заголовки
	KindPortScan      = "port_scan"      // nmap: перебор портов
)

// minProfile — минимальный профиль программы, при котором вид задачи
// разрешён. Каждый collector объявляет свой уровень «шумности» здесь.
var minProfile = map[string]config.Profile{
	KindSubdomainEnum: config.ProfilePassive, // пассивный OSINT
	KindDNSResolve:    config.ProfileLight,   // прямой DNS-запрос к резолверу
	KindHTTPProbe:     config.ProfileLight,   // одиночные HTTP-запросы к цели
	KindPortScan:      config.ProfileActive,  // активное сканирование портов
}

// MinProfile возвращает минимальный профиль для вида задачи и признак того,
// что вид известен. Неизвестный вид считаем требующим active — оркестратор
// не пропустит его случайно на пассивном профиле.
func MinProfile(kind string) (config.Profile, bool) {
	p, ok := minProfile[kind]
	if !ok {
		return config.ProfileActive, false
	}
	return p, true
}

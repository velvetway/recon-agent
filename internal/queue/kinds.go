package queue

import "github.com/velvet1way/recon-agent/internal/config"

// Виды задач разведки. Строки — стабильные ключи, на них завязаны диспетчер
// исполнителя и профильные ограничения ниже.
const (
	KindSubdomainEnum = "subdomain_enum" // BBOT, пассивный сбор поддоменов
	KindPassiveURLs   = "passive_urls"   // gau: URL из веб-архивов (пассивно)
	KindDNSResolve    = "dns_resolve"    // резолв имени в IP штатным резолвером
	KindHTTPProbe     = "http_probe"     // httpx: живой HTTP-сервис, tech, заголовки
	KindCrawl         = "crawl"          // katana: обход сайта, сбор URL и эндпоинтов
	KindPortScan      = "port_scan"      // nmap: перебор портов
	KindVulnScan      = "vuln_scan"      // nuclei: шаблонный скан (CWE/CVE в выводе)
)

// minProfile — минимальный профиль программы, при котором вид задачи
// разрешён. Каждый collector объявляет свой уровень «шумности» здесь.
var minProfile = map[string]config.Profile{
	KindSubdomainEnum: config.ProfilePassive, // пассивный OSINT
	KindPassiveURLs:   config.ProfilePassive, // URL из архивов, цель не трогаем
	KindDNSResolve:    config.ProfileLight,   // прямой DNS-запрос к резолверу
	KindHTTPProbe:     config.ProfileLight,   // одиночные HTTP-запросы к цели
	KindCrawl:         config.ProfileLight,   // обход сайта обычными запросами
	KindPortScan:      config.ProfileActive,  // активное сканирование портов
	KindVulnScan:      config.ProfileActive,  // активная проверка уязвимостей шаблонами
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

// Package config загружает scope-конфиг программы и настройки агента.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile — уровень «шумности» разведки. Программа задаёт максимально
// допустимый уровень; инструмент с более высоким требованием не запускается.
//
//	passive — только пассивный сбор, без обращений к целям (напр. OSINT-модули)
//	light   — лёгкие прямые обращения (DNS-резолв, HTTP-проб)
//	active  — активное сканирование (перебор портов, брутфорс путей)
type Profile string

const (
	ProfilePassive Profile = "passive"
	ProfileLight   Profile = "light"
	ProfileActive  Profile = "active"
)

var profileRank = map[Profile]int{ProfilePassive: 0, ProfileLight: 1, ProfileActive: 2}

// Valid сообщает, что профиль известен.
func (p Profile) Valid() bool { _, ok := profileRank[p]; return ok }

// AtLeast возвращает true, если p не ниже уровня need — то есть программа с
// профилем p разрешает инструмент, которому нужен минимум need.
func (p Profile) AtLeast(need Profile) bool { return profileRank[p] >= profileRank[need] }

// Scope описывает границы программы bug bounty.
type Scope struct {
	Program  string  `yaml:"program"`
	Platform string  `yaml:"platform"`
	Profile  Profile `yaml:"profile"`

	InScope struct {
		Domains   []string `yaml:"domains"`
		CIDRs     []string `yaml:"cidrs"`
		Wildcards bool     `yaml:"wildcards"`
	} `yaml:"in_scope"`

	OutOfScope struct {
		Domains []string `yaml:"domains"`
		CIDRs   []string `yaml:"cidrs"`
	} `yaml:"out_of_scope"`

	RateLimits RateLimits `yaml:"rate_limits"`
}

// RateLimits — ограничения скорости, чтобы не поймать бан на программе.
type RateLimits struct {
	GlobalRPS     int `yaml:"global_rps"`
	PerTargetRPS  int `yaml:"per_target_rps"`
	MaxConcurrent int `yaml:"max_concurrent_scans"`
}

// RootDomains возвращает корневые домены из in_scope без wildcard-префикса,
// пригодные как стартовые цели перечисления поддоменов.
func (s *Scope) RootDomains() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, d := range s.InScope.Domains {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// LoadScope читает scope-конфиг из YAML-файла.
func LoadScope(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение scope-конфига: %w", err)
	}

	var s Scope
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("разбор scope-конфига: %w", err)
	}

	if len(s.InScope.Domains) == 0 && len(s.InScope.CIDRs) == 0 {
		return nil, fmt.Errorf("scope пуст: не задано ни одного in_scope домена или CIDR")
	}

	// Профиль по умолчанию — самый безопасный.
	if s.Profile == "" {
		s.Profile = ProfilePassive
	}
	if !s.Profile.Valid() {
		return nil, fmt.Errorf("неизвестный profile %q: допустимо passive, light или active", s.Profile)
	}

	// Разумные значения по умолчанию.
	if s.RateLimits.GlobalRPS == 0 {
		s.RateLimits.GlobalRPS = 20
	}
	if s.RateLimits.PerTargetRPS == 0 {
		s.RateLimits.PerTargetRPS = 5
	}
	if s.RateLimits.MaxConcurrent == 0 {
		s.RateLimits.MaxConcurrent = 4
	}

	return &s, nil
}

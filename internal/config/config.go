// Package config загружает scope-конфиг программы и настройки агента.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope описывает границы программы bug bounty.
type Scope struct {
	Program  string `yaml:"program"`
	Platform string `yaml:"platform"`

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
	GlobalRPS       int `yaml:"global_rps"`
	PerTargetRPS    int `yaml:"per_target_rps"`
	MaxConcurrent   int `yaml:"max_concurrent_scans"`
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

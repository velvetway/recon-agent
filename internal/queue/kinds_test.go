package queue

import (
	"testing"

	"github.com/velvet1way/recon-agent/internal/config"
)

func TestMinProfile(t *testing.T) {
	cases := []struct {
		kind  string
		want  config.Profile
		known bool
	}{
		{KindSubdomainEnum, config.ProfilePassive, true},
		{KindDNSResolve, config.ProfileLight, true},
		{KindHTTPProbe, config.ProfileLight, true},
		{KindPortScan, config.ProfileActive, true},
		{"неизвестно", config.ProfileActive, false}, // fail-safe: требует active
	}
	for _, c := range cases {
		got, known := MinProfile(c.kind)
		if got != c.want || known != c.known {
			t.Errorf("MinProfile(%q) = %s,%v; want %s,%v", c.kind, got, known, c.want, c.known)
		}
	}
}

// Пассивный профиль пропускает только пассивные задачи, активный — все.
func TestProfileGatingMatrix(t *testing.T) {
	for kind := range minProfile {
		need, _ := MinProfile(kind)
		if !config.ProfileActive.AtLeast(need) {
			t.Errorf("active должен разрешать %q (need=%s)", kind, need)
		}
		if config.ProfilePassive.AtLeast(need) != (need == config.ProfilePassive) {
			t.Errorf("passive и %q: разрешение не совпадает с профилем задачи", kind)
		}
	}
}

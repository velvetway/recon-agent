package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileAtLeast(t *testing.T) {
	cases := []struct {
		have, need Profile
		want       bool
	}{
		{ProfilePassive, ProfilePassive, true},
		{ProfilePassive, ProfileLight, false},
		{ProfilePassive, ProfileActive, false},
		{ProfileLight, ProfilePassive, true},
		{ProfileLight, ProfileActive, false},
		{ProfileActive, ProfileActive, true},
		{ProfileActive, ProfilePassive, true},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.need); got != c.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
}

func TestLoadScopeProfile(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "scope.yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := "in_scope:\n  domains: [example.com]\n"

	// Профиль по умолчанию — passive.
	s, err := LoadScope(write(t, base))
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if s.Profile != ProfilePassive {
		t.Errorf("профиль по умолчанию = %q, want passive", s.Profile)
	}

	s, err = LoadScope(write(t, base+"profile: active\n"))
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if s.Profile != ProfileActive {
		t.Errorf("профиль = %q, want active", s.Profile)
	}

	if _, err := LoadScope(write(t, base+"profile: loud\n")); err == nil {
		t.Error("неизвестный профиль должен вызывать ошибку")
	}
}

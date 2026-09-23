package scope

import (
	"testing"

	"github.com/velvet1way/recon-agent/internal/config"
)

func testGuard(t *testing.T) *Guard {
	t.Helper()
	s := &config.Scope{}
	s.InScope.Domains = []string{"*.standoff365.com", "standoff365.com"}
	s.InScope.CIDRs = []string{"203.0.113.0/24"}
	s.InScope.Wildcards = true
	s.OutOfScope.Domains = []string{"blog.standoff365.com"}
	s.OutOfScope.CIDRs = []string{"203.0.113.128/25"}

	g, err := New(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestCheckDomain(t *testing.T) {
	g := testGuard(t)
	cases := []struct {
		target string
		want   bool
	}{
		{"standoff365.com", true},
		{"api.standoff365.com", true},
		{"deep.sub.standoff365.com", true},
		{"STANDOFF365.COM", true},          // регистр не важен
		{"blog.standoff365.com", false},    // явный out_of_scope
		{"evil.com", false},                // вне скоупа
		{"notstandoff365.com", false},      // не суффикс
		{"standoff365.com.evil.com", false},// подмена суффикса
		{"", false},
	}
	for _, c := range cases {
		if got := g.Allowed(c.target); got != c.want {
			t.Errorf("Allowed(%q) = %v, want %v (%s)", c.target, got, c.want, g.Check(c.target).Reason)
		}
	}
}

func TestCheckIP(t *testing.T) {
	g := testGuard(t)
	cases := []struct {
		target string
		want   bool
	}{
		{"203.0.113.10", true},   // in_scope /24
		{"203.0.113.200", false}, // попадает в out_of_scope /25
		{"198.51.100.1", false},  // вне скоупа
	}
	for _, c := range cases {
		if got := g.Allowed(c.target); got != c.want {
			t.Errorf("Allowed(%q) = %v, want %v (%s)", c.target, got, c.want, g.Check(c.target).Reason)
		}
	}
}

func TestWildcardBaseDomainDisabled(t *testing.T) {
	s := &config.Scope{}
	s.InScope.Domains = []string{"*.standoff365.com"}
	s.InScope.Wildcards = false // база не покрывается
	g, err := New(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Allowed("standoff365.com") {
		t.Error("база домена не должна быть в скоупе при wildcards=false")
	}
	if !g.Allowed("api.standoff365.com") {
		t.Error("поддомен должен быть в скоупе")
	}
}

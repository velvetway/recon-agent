package orchestrator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scope"
)

func testOrch(t *testing.T, profile config.Profile) (*Orchestrator, *int) {
	t.Helper()
	s := &config.Scope{}
	s.InScope.Domains = []string{"*.example.com", "example.com"}
	s.InScope.Wildcards = true
	s.InScope.CIDRs = []string{"203.0.113.0/24"}
	g, err := scope.New(s)
	if err != nil {
		t.Fatal(err)
	}
	var submitted int
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q := queue.New(1, queue.NewRateLimiter(1000, 1000), func(ctx context.Context, tk queue.Task) error {
		submitted++
		return nil
	}, log)
	q.Start(context.Background())
	t.Cleanup(func() { q.WaitIdle(context.Background()); q.Shutdown() })
	return New(g, q, profile, log), &submitted
}

// Профиль программы отсекает задачи, которые шумнее допустимого.
func TestEnqueueProfileGate(t *testing.T) {
	o, _ := testOrch(t, config.ProfilePassive)
	cases := []struct {
		kind  string
		allow bool
	}{
		{queue.KindSubdomainEnum, true}, // passive
		{queue.KindDNSResolve, false},   // light
		{queue.KindPortScan, false},     // active
		{"custom_active_tool", false},   // неизвестный → требует active
	}
	for _, c := range cases {
		if got := o.Enqueue(queue.Task{Kind: c.kind, Target: "a.example.com"}); got != c.allow {
			t.Errorf("passive Enqueue(%q) = %v, want %v", c.kind, got, c.allow)
		}
	}
}

// На active проходят все известные виды, но scope-guard и дедуп остаются.
func TestEnqueueActiveStillGuards(t *testing.T) {
	o, _ := testOrch(t, config.ProfileActive)
	if !o.Enqueue(queue.Task{Kind: queue.KindPortScan, Target: "203.0.113.5"}) {
		t.Error("active должен пропустить port_scan в скоупе")
	}
	// Повтор той же задачи — дедуп.
	if o.Enqueue(queue.Task{Kind: queue.KindPortScan, Target: "203.0.113.5"}) {
		t.Error("повтор задачи должен быть отброшен дедупом")
	}
	// Цель вне скоупа — блок scope-guard, даже на active.
	if o.Enqueue(queue.Task{Kind: queue.KindHTTPProbe, Target: "evil.com"}) {
		t.Error("scope-guard должен блокировать цель вне скоупа")
	}
}

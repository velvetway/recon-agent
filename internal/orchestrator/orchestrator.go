// Package orchestrator принимает решения о следующих шагах разведки.
// Здесь находится ПЕРВАЯ проверка scope-guard — перед постановкой задачи
// в очередь. Вторая проверка живёт в scanner (исполнитель).
//
// Цикл работы: observe (посмотреть в граф) → decide (выбрать шаг) →
// act (поставить задачу) → update (граф обновится исполнителем).
// LLM подключается поверх этого цикла через MCP-инструменты.
package orchestrator

import (
	"context"
	"log/slog"
	"sync"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scope"
)

// Orchestrator ставит задачи разведки, соблюдая скоуп и профиль программы.
type Orchestrator struct {
	guard   *scope.Guard
	queue   *queue.Queue
	profile config.Profile
	log     *slog.Logger
	seen    sync.Map // ключ kind|target -> struct{}, дедуп задач
}

// New создаёт оркестратор. profile — максимально допустимый уровень «шумности».
func New(guard *scope.Guard, q *queue.Queue, profile config.Profile, log *slog.Logger) *Orchestrator {
	return &Orchestrator{guard: guard, queue: q, profile: profile, log: log}
}

// Enqueue ставит задачу в очередь после трёх проверок: дедуп, профиль
// программы, scope-guard. Возвращает false, если задача отклонена.
func (o *Orchestrator) Enqueue(t queue.Task) bool {
	key := t.Kind + "|" + t.Target
	if _, dup := o.seen.LoadOrStore(key, struct{}{}); dup {
		return false
	}
	// Профильная проверка: инструмент шумнее, чем разрешает программа, не
	// ставится. Неизвестный вид задачи требует active и на passive не пройдёт.
	need, known := queue.MinProfile(t.Kind)
	if !known {
		o.log.Warn("неизвестный вид задачи, требуется профиль active",
			"kind", t.Kind, "target", t.Target)
	}
	if !o.profile.AtLeast(need) {
		o.log.Info("задача пропущена: выше профиля программы",
			"kind", t.Kind, "target", t.Target, "need", need, "profile", o.profile)
		return false
	}
	if d := o.guard.Check(t.Target); !d.Allowed {
		o.log.Warn("scope-guard заблокировал постановку задачи",
			"kind", t.Kind, "target", t.Target, "reason", d.Reason)
		return false
	}
	o.queue.Submit(t)
	o.log.Info("задача поставлена", "kind", t.Kind, "target", t.Target)
	return true
}

// SeedFromScope ставит стартовые задачи по каждому корневому домену: пассивный
// сбор поддоменов (bbot) и URL из архивов (gau). Профильный гейт сам отсеет то,
// что выше профиля программы.
func (o *Orchestrator) SeedFromScope(ctx context.Context, rootDomains []string) {
	for _, d := range rootDomains {
		o.Enqueue(queue.Task{Kind: queue.KindSubdomainEnum, Target: d})
		o.Enqueue(queue.Task{Kind: queue.KindPassiveURLs, Target: d})
	}
}

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

	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scope"
)

// Orchestrator ставит задачи разведки, соблюдая скоуп.
type Orchestrator struct {
	guard *scope.Guard
	queue *queue.Queue
	log   *slog.Logger
}

// New создаёт оркестратор.
func New(guard *scope.Guard, q *queue.Queue, log *slog.Logger) *Orchestrator {
	return &Orchestrator{guard: guard, queue: q, log: log}
}

// Enqueue ставит задачу в очередь после проверки scope-guard.
// Возвращает false, если цель заблокирована.
func (o *Orchestrator) Enqueue(t queue.Task) bool {
	if d := o.guard.Check(t.Target); !d.Allowed {
		o.log.Warn("scope-guard заблокировал постановку задачи",
			"kind", t.Kind, "target", t.Target, "reason", d.Reason)
		return false
	}
	o.queue.Submit(t)
	o.log.Info("задача поставлена", "kind", t.Kind, "target", t.Target)
	return true
}

// SeedFromScope ставит стартовые задачи перечисления поддоменов
// по каждому корневому домену из скоупа.
func (o *Orchestrator) SeedFromScope(ctx context.Context, rootDomains []string) {
	for _, d := range rootDomains {
		o.Enqueue(queue.Task{Kind: "subdomain_enum", Target: d})
	}
}

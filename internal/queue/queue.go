// Package queue — асинхронная очередь задач разведки с пулом воркеров,
// ограничением параллелизма и rate-limiting.
package queue

import (
	"context"
	"log/slog"
	"sync"
)

// Task — единица работы разведки.
type Task struct {
	Kind   string // напр. "subdomain_enum", "port_scan"
	Target string // домен или IP
}

// Handler выполняет задачу. Реализуется исполнителем (scanner).
type Handler func(ctx context.Context, t Task) error

// Queue распределяет задачи по воркерам с учётом лимитов.
type Queue struct {
	tasks   chan Task
	limiter *RateLimiter
	handler Handler
	workers int
	wg      sync.WaitGroup
	log     *slog.Logger
}

// New создаёт очередь. workers — максимум одновременных сканов.
func New(workers int, limiter *RateLimiter, handler Handler, log *slog.Logger) *Queue {
	return &Queue{
		tasks:   make(chan Task, 256),
		limiter: limiter,
		handler: handler,
		workers: workers,
		log:     log,
	}
}

// Start запускает пул воркеров.
func (q *Queue) Start(ctx context.Context) {
	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.worker(ctx, i)
	}
}

// Submit ставит задачу в очередь. Не блокирует, пока буфер не полон.
func (q *Queue) Submit(t Task) {
	q.tasks <- t
}

// Shutdown закрывает приём задач и ждёт завершения воркеров.
func (q *Queue) Shutdown() {
	close(q.tasks)
	q.wg.Wait()
}

func (q *Queue) worker(ctx context.Context, id int) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-q.tasks:
			if !ok {
				return
			}
			if err := q.limiter.Wait(ctx, t.Target); err != nil {
				return // контекст отменён
			}
			if err := q.handler(ctx, t); err != nil {
				q.log.Error("задача провалена", "worker", id, "kind", t.Kind, "target", t.Target, "err", err)
			}
		}
	}
}

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
//
// Очередь отслеживает число незавершённых задач (поставленных, но ещё не
// обработанных). Так как follow-up задачи ставятся из обработчика — то есть
// до того, как родительская задача считается завершённой, — счётчик доходит
// до нуля только когда работы действительно не осталось. Это позволяет
// завершить прогон сам по себе, не дожидаясь сигнала (см. WaitIdle).
type Queue struct {
	tasks   chan Task
	limiter *RateLimiter
	handler Handler
	workers int
	wg      sync.WaitGroup
	log     *slog.Logger

	mu      sync.Mutex
	cond    *sync.Cond
	pending int  // незавершённых задач
	closed  bool // приём задач закрыт
}

// New создаёт очередь. workers — максимум одновременных сканов.
func New(workers int, limiter *RateLimiter, handler Handler, log *slog.Logger) *Queue {
	q := &Queue{
		tasks:   make(chan Task, 256),
		limiter: limiter,
		handler: handler,
		workers: workers,
		log:     log,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Start запускает пул воркеров.
func (q *Queue) Start(ctx context.Context) {
	// Разбудить ожидающих WaitIdle при отмене контекста, чтобы прогон не завис.
	go func() {
		<-ctx.Done()
		q.mu.Lock()
		q.cond.Broadcast()
		q.mu.Unlock()
	}()
	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.worker(ctx, i)
	}
}

// Submit ставит задачу в очередь. После Shutdown задачи молча отбрасываются:
// поздний follow-up из обработчика на этапе остановки — не ошибка.
func (q *Queue) Submit(t Task) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.pending++
	q.mu.Unlock()
	q.tasks <- t
}

// done отмечает задачу завершённой и будит WaitIdle, когда работы не осталось.
func (q *Queue) done() {
	q.mu.Lock()
	q.pending--
	if q.pending == 0 {
		q.cond.Broadcast()
	}
	q.mu.Unlock()
}

// WaitIdle блокируется, пока не завершатся все задачи (счётчик дошёл до нуля)
// либо не будет отменён контекст. Возвращает true, если очередь опустела сама.
func (q *Queue) WaitIdle(ctx context.Context) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.pending > 0 && ctx.Err() == nil {
		q.cond.Wait()
	}
	return q.pending == 0
}

// Shutdown закрывает приём задач и ждёт завершения воркеров.
func (q *Queue) Shutdown() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.mu.Unlock()
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
			q.run(ctx, id, t)
		}
	}
}

// run выполняет одну задачу и всегда отмечает её завершённой.
func (q *Queue) run(ctx context.Context, id int, t Task) {
	defer q.done()
	if err := q.limiter.Wait(ctx, t.Target); err != nil {
		return // контекст отменён
	}
	if err := q.handler(ctx, t); err != nil {
		q.log.Error("задача провалена", "worker", id, "kind", t.Kind, "target", t.Target, "err", err)
	}
}

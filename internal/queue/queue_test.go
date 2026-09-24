package queue

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func testQueue(t *testing.T, handler Handler) *Queue {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Лимитер с большими значениями, чтобы не влиял на тайминг теста.
	return New(4, NewRateLimiter(1000, 1000), handler, log)
}

// Прогон завершается сам, когда очередь опустела, включая follow-up задачи,
// поставленные из обработчиков.
func TestWaitIdleDrainsFollowups(t *testing.T) {
	var done int32
	var q *Queue
	handler := func(ctx context.Context, tk Task) error {
		atomic.AddInt32(&done, 1)
		// Каждая из двух корневых задач порождает три потомка (один уровень).
		if tk.Kind == "root" {
			for i := 0; i < 3; i++ {
				q.Submit(Task{Kind: "child", Target: tk.Target})
			}
		}
		return nil
	}
	q = testQueue(t, handler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q.Start(ctx)
	q.Submit(Task{Kind: "root", Target: "a"})
	q.Submit(Task{Kind: "root", Target: "b"})

	if !q.WaitIdle(ctx) {
		t.Fatal("WaitIdle вернул false — очередь не опустела")
	}
	q.Shutdown()
	// 2 корневые + 2*3 потомка.
	if got := atomic.LoadInt32(&done); got != 8 {
		t.Errorf("выполнено задач = %d, want 8", got)
	}
}

// Отмена контекста прерывает ожидание, даже если задачи ещё «висят».
func TestWaitIdleContextCancel(t *testing.T) {
	block := make(chan struct{})
	handler := func(ctx context.Context, tk Task) error {
		<-block // держим воркер, пока тест не отпустит
		return nil
	}
	q := testQueue(t, handler)
	ctx, cancel := context.WithCancel(context.Background())
	q.Start(ctx)
	q.Submit(Task{Kind: "x", Target: "a"})

	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if q.WaitIdle(ctx) {
		t.Error("WaitIdle вернул true при отмене — ожидалось прерывание")
	}
	close(block)
	q.Shutdown()
}

// Submit после Shutdown не паникует и молча отбрасывается.
func TestSubmitAfterShutdown(t *testing.T) {
	q := testQueue(t, func(ctx context.Context, tk Task) error { return nil })
	q.Start(context.Background())
	q.Submit(Task{Kind: "x", Target: "a"})
	q.WaitIdle(context.Background())
	q.Shutdown()
	q.Submit(Task{Kind: "x", Target: "b"}) // не должно паниковать
}

package mcpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/graph"
	"github.com/velvet1way/recon-agent/internal/queue"
	"github.com/velvet1way/recon-agent/internal/scope"
)

// --- Фейки ---

type fakeEnq struct {
	tasks  []queue.Task
	accept bool
}

func (f *fakeEnq) Enqueue(t queue.Task) bool {
	f.tasks = append(f.tasks, t)
	return f.accept
}

type fakeGraph struct {
	rows    []map[string]any
	queryEr error

	created  bool
	findErr  error
	lastFind graph.Finding
}

func (f *fakeGraph) RunNamedQuery(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
	return f.rows, f.queryEr
}

func (f *fakeGraph) AddFinding(_ context.Context, fi graph.Finding) (bool, error) {
	f.lastFind = fi
	return f.created, f.findErr
}

// newTestServer собирает сервер со скоупом example.com (+ поддомены) и
// out-of-scope admin.example.com; in_scope CIDR 10.0.0.0/8.
func newTestServer(t *testing.T, enq Enqueuer, g Graph) *Server {
	t.Helper()
	sc := &config.Scope{Program: "test", Platform: "manual"}
	sc.InScope.Domains = []string{"*.example.com", "example.com"}
	sc.InScope.CIDRs = []string{"10.0.0.0/8"}
	sc.InScope.Wildcards = true
	sc.OutOfScope.Domains = []string{"admin.example.com"}
	guard, err := scope.New(sc)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	log := slog.New(slog.NewTextHandler(discard{}, nil))
	return New(sc, guard, g, enq, log)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func call(t *testing.T, s *Server, tool string, args map[string]any) map[string]any {
	t.Helper()
	var td *toolDef
	for i := range s.tools {
		if s.tools[i].Name == tool {
			td = &s.tools[i]
		}
	}
	if td == nil {
		t.Fatalf("инструмент %q не найден", tool)
	}
	res, err := td.Handler(context.Background(), args)
	if err != nil {
		t.Fatalf("%s вернул ошибку: %v", tool, err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("%s вернул не map: %T", tool, res)
	}
	return m
}

// --- enqueue_task ---

func TestEnqueuePortScanRequiresIP(t *testing.T) {
	enq := &fakeEnq{accept: true}
	s := newTestServer(t, enq, &fakeGraph{})

	// Домен в скоупе, но для port_scan нужен IP → отказ ещё до scope-guard.
	got := call(t, s, "enqueue_task", map[string]any{"kind": "port_scan", "target": "api.example.com"})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused для домена в port_scan, получено %v", got)
	}
	if len(enq.tasks) != 0 {
		t.Fatalf("задача не должна была ставиться, поставлено %d", len(enq.tasks))
	}

	// IP в скоупе — принимается.
	got = call(t, s, "enqueue_task", map[string]any{"kind": "port_scan", "target": "10.1.2.3"})
	if got["status"] != "accepted" {
		t.Fatalf("ожидался accepted для IP в скоупе, получено %v", got)
	}
	if len(enq.tasks) != 1 || enq.tasks[0].Kind != "port_scan" || enq.tasks[0].Target != "10.1.2.3" {
		t.Fatalf("неверная поставленная задача: %+v", enq.tasks)
	}
}

func TestEnqueueHostKindRejectsIP(t *testing.T) {
	enq := &fakeEnq{accept: true}
	s := newTestServer(t, enq, &fakeGraph{})
	got := call(t, s, "enqueue_task", map[string]any{"kind": "subdomain_enum", "target": "10.1.2.3"})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused: доменная задача с IP, получено %v", got)
	}
}

func TestEnqueueUnknownKind(t *testing.T) {
	s := newTestServer(t, &fakeEnq{accept: true}, &fakeGraph{})
	got := call(t, s, "enqueue_task", map[string]any{"kind": "rce_exploit", "target": "api.example.com"})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused для неизвестного вида, получено %v", got)
	}
}

func TestEnqueueOutOfScopeBlocked(t *testing.T) {
	enq := &fakeEnq{accept: true}
	s := newTestServer(t, enq, &fakeGraph{})
	got := call(t, s, "enqueue_task", map[string]any{"kind": "http_probe", "target": "admin.example.com"})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused для out-of-scope цели, получено %v", got)
	}
	got = call(t, s, "enqueue_task", map[string]any{"kind": "http_probe", "target": "evil.com"})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused для цели вне скоупа, получено %v", got)
	}
	if len(enq.tasks) != 0 {
		t.Fatalf("вне скоупа ничего не должно ставиться, поставлено %d", len(enq.tasks))
	}
}

func TestEnqueueDuplicate(t *testing.T) {
	enq := &fakeEnq{accept: false} // очередь говорит "дубликат"
	s := newTestServer(t, enq, &fakeGraph{})
	got := call(t, s, "enqueue_task", map[string]any{"kind": "dns_resolve", "target": "api.example.com"})
	if got["status"] != "duplicate" {
		t.Fatalf("ожидался duplicate, получено %v", got)
	}
}

// --- mark_finding ---

func TestMarkFindingValidation(t *testing.T) {
	s := newTestServer(t, &fakeEnq{accept: true}, &fakeGraph{created: true})

	// Пустое доказательство — отказ.
	got := call(t, s, "mark_finding", map[string]any{
		"service_url": "https://api.example.com", "type": "exposed-config",
		"severity": "high", "evidence": "",
	})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused при пустом evidence, получено %v", got)
	}

	// Неверный severity — отказ.
	got = call(t, s, "mark_finding", map[string]any{
		"service_url": "https://api.example.com", "type": "exposed-config",
		"severity": "apocalyptic", "evidence": "открыт /.git",
	})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused при неверном severity, получено %v", got)
	}

	// Хост вне скоупа — отказ.
	got = call(t, s, "mark_finding", map[string]any{
		"service_url": "https://evil.com", "type": "exposed-config",
		"severity": "high", "evidence": "открыт /.git",
	})
	if got["status"] != "refused" {
		t.Fatalf("ожидался refused для хоста вне скоупа, получено %v", got)
	}
}

func TestMarkFindingCreated(t *testing.T) {
	g := &fakeGraph{created: true}
	s := newTestServer(t, &fakeEnq{accept: true}, g)
	got := call(t, s, "mark_finding", map[string]any{
		"service_url": "https://api.example.com", "type": "exposed-config",
		"severity": "High", "evidence": "открыт /.git/config",
	})
	if got["status"] != "created" {
		t.Fatalf("ожидался created, получено %v", got)
	}
	if g.lastFind.Severity != "high" {
		t.Fatalf("severity должен нормализоваться в lower, получено %q", g.lastFind.Severity)
	}
}

// --- get_scope ---

func TestGetScope(t *testing.T) {
	s := newTestServer(t, &fakeEnq{accept: true}, &fakeGraph{})
	got := call(t, s, "get_scope", nil)
	ops, ok := got["allowed_operations"].([]string)
	if !ok || len(ops) != 4 {
		t.Fatalf("ожидалось 4 операции, получено %v", got["allowed_operations"])
	}
	if got["scope_version"] == "" {
		t.Fatal("scope_version не должен быть пустым")
	}
}

// --- JSON-RPC диспетчеризация ---

func TestDispatchInitializeAndToolsList(t *testing.T) {
	s := newTestServer(t, &fakeEnq{accept: true}, &fakeGraph{})

	resp, send := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if !send || resp.Error != nil {
		t.Fatalf("initialize: send=%v err=%v", send, resp.Error)
	}

	resp, send = s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !send || resp.Error != nil {
		t.Fatalf("tools/list: send=%v err=%v", send, resp.Error)
	}
	m := resp.Result.(map[string]any)
	tools := m["tools"].([]map[string]any)
	if len(tools) != 4 {
		t.Fatalf("ожидалось 4 инструмента, получено %d", len(tools))
	}
}

func TestDispatchNotificationNoReply(t *testing.T) {
	s := newTestServer(t, &fakeEnq{accept: true}, &fakeGraph{})
	_, send := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if send {
		t.Fatal("на уведомление ответ отправляться не должен")
	}
}

func TestDispatchToolCall(t *testing.T) {
	enq := &fakeEnq{accept: true}
	s := newTestServer(t, enq, &fakeGraph{})
	req := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"enqueue_task","arguments":{"kind":"port_scan","target":"10.0.0.5"}}}`)
	resp, send := s.handle(context.Background(), req)
	if !send || resp.Error != nil {
		t.Fatalf("tools/call: send=%v err=%v", send, resp.Error)
	}
	m := resp.Result.(map[string]any)
	content := m["content"].([]map[string]any)
	var payload map[string]any
	if err := json.Unmarshal([]byte(content[0]["text"].(string)), &payload); err != nil {
		t.Fatalf("разбор content: %v", err)
	}
	if payload["status"] != "accepted" {
		t.Fatalf("ожидался accepted, получено %v", payload)
	}
	if len(enq.tasks) != 1 {
		t.Fatalf("задача должна быть поставлена, поставлено %d", len(enq.tasks))
	}
}

func TestDispatchUnknownMethod(t *testing.T) {
	s := newTestServer(t, &fakeEnq{accept: true}, &fakeGraph{})
	resp, send := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":9,"method":"nope"}`))
	if !send || resp.Error == nil || resp.Error.Code != codeMethodMissing {
		t.Fatalf("ожидалась ошибка method-not-found, получено %+v", resp)
	}
}

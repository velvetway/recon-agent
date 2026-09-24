package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// Реализация транспорта MCP по stdio: построчный JSON-RPC 2.0.
// Протокольные сообщения идут в stdout, логи агента — в stderr, поэтому
// поток не загрязняется.

const protocolVersion = "2024-11-05"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC коды ошибок.
const (
	codeParseError    = -32700
	codeInvalidReq    = -32600
	codeMethodMissing = -32601
	codeInvalidParams = -32602
	codeInternal      = -32603
)

// ServeStdio читает запросы из r и пишет ответы в w до EOF или отмены ctx.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	enc := json.NewEncoder(w)

	s.log.Info("MCP-сервер запущен (stdio)", "tools", len(s.tools))
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		resp, send := s.handle(ctx, line)
		if !send {
			continue // уведомление — ответа не требуется
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("запись ответа: %w", err)
		}
	}
	return sc.Err()
}

// handle разбирает одно сообщение и возвращает ответ. Второе значение —
// нужно ли его отправлять (для уведомлений — нет). Выделено отдельно,
// чтобы диспетчеризация тестировалась без реального stdio.
func (s *Server) handle(ctx context.Context, line []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return errResp(nil, codeParseError, "невалидный JSON"), true
	}
	// Уведомления (id отсутствует) ответа не требуют.
	notification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		return okResp(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "recon-agent", "version": "0.1.0"},
		}), true

	case "notifications/initialized":
		return rpcResponse{}, false

	case "ping":
		return okResp(req.ID, map[string]any{}), !notification

	case "tools/list":
		return okResp(req.ID, map[string]any{"tools": s.toolList()}), true

	case "tools/call":
		return s.handleToolCall(ctx, req), true

	default:
		if notification {
			return rpcResponse{}, false
		}
		return errResp(req.ID, codeMethodMissing, "неизвестный метод: "+req.Method), true
	}
}

func (s *Server) toolList() []map[string]any {
	out := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return out
}

func (s *Server) handleToolCall(ctx context.Context, req rpcRequest) rpcResponse {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, codeInvalidParams, "невалидные params")
	}
	tool := s.lookupTool(p.Name)
	if tool == nil {
		return errResp(req.ID, codeInvalidParams, "неизвестный инструмент: "+p.Name)
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}

	result, err := tool.Handler(ctx, p.Arguments)
	if err != nil {
		// Ошибка инструмента возвращается как isError-контент, а не как
		// протокольная ошибка: LLM видит текст и может отреагировать.
		s.log.Warn("ошибка инструмента", "tool", p.Name, "err", err)
		return okResp(req.ID, toolContent(err.Error(), true))
	}
	payload, mErr := json.Marshal(result)
	if mErr != nil {
		return errResp(req.ID, codeInternal, "сериализация результата")
	}
	return okResp(req.ID, toolContent(string(payload), false))
}

func (s *Server) lookupTool(name string) *toolDef {
	for i := range s.tools {
		if s.tools[i].Name == name {
			return &s.tools[i]
		}
	}
	return nil
}

func toolContent(text string, isErr bool) map[string]any {
	m := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
	if isErr {
		m["isError"] = true
	}
	return m
}

func okResp(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errResp(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

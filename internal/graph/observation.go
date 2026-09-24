package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Observation — единый вид наблюдения: «инструмент tool увидел у актива
// asset факт kind со значением value». Все collector'ы пишут наблюдения
// наравне со своими узлами; из них строится архив прогона (internal/archive),
// а их ID — это evidence_ids, на которые обязаны ссылаться выводы о CWE.
//
//	(:Run)-[:HAS_OBSERVATION]->(:Observation)
type Observation struct {
	ID       string // детерминированный, см. ObservationID
	RunID    string
	Asset    string // хост или IP, к которому относится факт
	Tool     string // bbot, dns, httpx, nmap...
	Kind     string // subdomain, dns_a, http_service, tech, open_port...
	Value    string
	Evidence string // короткая выдержка из вывода инструмента
	TS       int64  // unix-время в миллисекундах (ставит Neo4j при записи)
}

// ObservationID — стабильный ID наблюдения в пределах прогона: одинаковый
// факт, записанный дважды, остаётся одним узлом.
func ObservationID(runID, asset, tool, kind, value string) string {
	h := sha256.Sum256([]byte(runID + "\x00" + asset + "\x00" + tool + "\x00" + kind + "\x00" + value))
	return hex.EncodeToString(h[:8])
}

// AddObservation записывает наблюдение и привязывает его к прогону.
func (s *Store) AddObservation(ctx context.Context, o Observation) error {
	if o.RunID == "" || o.Asset == "" || o.Tool == "" || o.Kind == "" {
		return fmt.Errorf("наблюдение без run_id, asset, tool или kind: %+v", o)
	}
	if o.ID == "" {
		o.ID = ObservationID(o.RunID, o.Asset, o.Tool, o.Kind, o.Value)
	}
	return s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		_, err := tx.Run(ctx, `
			MERGE (r:Run {id: $run})
			MERGE (o:Observation {id: $id})
			ON CREATE SET o.ts = timestamp()
			SET o.run_id = $run, o.asset = $asset, o.tool = $tool,
			    o.kind = $kind, o.value = $value, o.evidence = $evidence
			MERGE (r)-[:HAS_OBSERVATION]->(o)
		`, map[string]any{
			"id": o.ID, "run": o.RunID, "asset": o.Asset, "tool": o.Tool,
			"kind": o.Kind, "value": o.Value, "evidence": o.Evidence,
		})
		return err
	})
}

// RunInfo — сведения о прогоне для манифеста архива.
type RunInfo struct {
	ID        string
	Program   string
	Platform  string
	Profile   string
	StartedAt int64 // unix-мс
}

// Run возвращает сведения о прогоне.
func (s *Store) Run(ctx context.Context, runID string) (RunInfo, error) {
	var ri RunInfo
	err := s.read(ctx, func(tx neo4j.ManagedTransaction) error {
		res, err := tx.Run(ctx, `
			MATCH (r:Run {id: $run})
			OPTIONAL MATCH (p:Program)-[:HAS_RUN]->(r)
			RETURN r.id AS id, coalesce(p.name, '') AS program, coalesce(p.platform, '') AS platform,
			       coalesce(r.profile, '') AS profile, coalesce(r.started_at, 0) AS started
		`, map[string]any{"run": runID})
		if err != nil {
			return err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return fmt.Errorf("прогон %q не найден: %w", runID, err)
		}
		ri = RunInfo{
			ID:        str(rec, "id"),
			Program:   str(rec, "program"),
			Platform:  str(rec, "platform"),
			Profile:   str(rec, "profile"),
			StartedAt: i64(rec, "started"),
		}
		return nil
	})
	return ri, err
}

// LatestRunID возвращает ID самого свежего прогона.
func (s *Store) LatestRunID(ctx context.Context) (string, error) {
	var id string
	err := s.read(ctx, func(tx neo4j.ManagedTransaction) error {
		res, err := tx.Run(ctx, `MATCH (r:Run) RETURN r.id AS id ORDER BY r.started_at DESC LIMIT 1`, nil)
		if err != nil {
			return err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return fmt.Errorf("в графе нет ни одного прогона")
		}
		id = str(rec, "id")
		return nil
	})
	return id, err
}

// Observations возвращает все наблюдения прогона в стабильном порядке.
func (s *Store) Observations(ctx context.Context, runID string) ([]Observation, error) {
	var out []Observation
	err := s.read(ctx, func(tx neo4j.ManagedTransaction) error {
		res, err := tx.Run(ctx, `
			MATCH (:Run {id: $run})-[:HAS_OBSERVATION]->(o:Observation)
			RETURN o.id AS id, o.asset AS asset, o.tool AS tool, o.kind AS kind,
			       coalesce(o.value, '') AS value, coalesce(o.evidence, '') AS evidence,
			       coalesce(o.ts, 0) AS ts
			ORDER BY o.asset, o.tool, o.kind, o.value
		`, map[string]any{"run": runID})
		if err != nil {
			return err
		}
		for res.Next(ctx) {
			rec := res.Record()
			out = append(out, Observation{
				ID: str(rec, "id"), RunID: runID, Asset: str(rec, "asset"),
				Tool: str(rec, "tool"), Kind: str(rec, "kind"), Value: str(rec, "value"),
				Evidence: str(rec, "evidence"), TS: i64(rec, "ts"),
			})
		}
		return res.Err()
	})
	return out, err
}

func str(rec *neo4j.Record, key string) string {
	if v, ok := rec.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func i64(rec *neo4j.Record, key string) int64 {
	if v, ok := rec.Get(key); ok {
		if n, ok := v.(int64); ok {
			return n
		}
	}
	return 0
}

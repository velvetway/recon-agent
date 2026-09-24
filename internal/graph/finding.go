package graph

import (
	"context"
	"errors"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// ErrServiceNotFound возвращается, когда находку пытаются привязать к
// сервису, которого нет в графе. Это защита от "галлюцинированных"
// находок: находка регистрируется только на реально обнаруженном сервисе.
var ErrServiceNotFound = errors.New("сервис не найден в графе")

// Finding — кандидат-находка уязвимости на HTTP-сервисе.
// Дедуп идёт по паре (service_url, type): повторный вызов обновляет
// существующий узел, а не плодит дубликаты.
type Finding struct {
	ServiceURL string // url сервиса из графа (Service.url)
	Type       string // класс находки, напр. "exposed-config", "default-creds"
	Severity   string // info|low|medium|high|critical
	Evidence   string // доказательство: где и что найдено
}

// AddFinding создаёт или обновляет узел Finding, привязанный к сервису.
// Возвращает created=true, если узел создан впервые (не дубликат).
// Если сервиса с таким url в графе нет — ErrServiceNotFound.
func (s *Store) AddFinding(ctx context.Context, f Finding) (bool, error) {
	var created bool
	err := s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		// 1. Сервис должен существовать.
		res, err := tx.Run(ctx,
			"MATCH (svc:Service {url: $url}) RETURN count(svc) AS c",
			map[string]any{"url": f.ServiceURL})
		if err != nil {
			return err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return err
		}
		if c, _ := rec.Get("c"); c.(int64) == 0 {
			return ErrServiceNotFound
		}

		// 2. Была ли уже такая находка (для флага created).
		res, err = tx.Run(ctx, `
			OPTIONAL MATCH (:Service {url: $url})-[:HAS_FINDING]->(f:Finding {type: $ftype})
			RETURN f IS NOT NULL AS existed
		`, map[string]any{"url": f.ServiceURL, "ftype": f.Type})
		if err != nil {
			return err
		}
		rec, err = res.Single(ctx)
		if err != nil {
			return err
		}
		existed, _ := rec.Get("existed")
		created = !existed.(bool)

		// 3. Upsert самой находки.
		_, err = tx.Run(ctx, `
			MATCH (svc:Service {url: $url})
			MERGE (svc)-[:HAS_FINDING]->(f:Finding {type: $ftype, service_url: $url})
			ON CREATE SET f.status = 'candidate', f.created_at = timestamp()
			SET f.severity = $sev, f.evidence = $evidence, f.updated_at = timestamp()
		`, map[string]any{
			"url":      f.ServiceURL,
			"ftype":    f.Type,
			"sev":      f.Severity,
			"evidence": f.Evidence,
		})
		return err
	})
	return created, err
}

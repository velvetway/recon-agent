package graph

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// queryLimit ограничивает размер ответа именованного запроса: LLM не должна
// получать неограниченный дамп графа за один вызов.
const queryLimit = 500

// namedQuery — заранее заданный read-запрос. LLM не пишет Cypher сама,
// а выбирает запрос по имени и передаёт типизированные параметры. Так граф
// доступен модели только через фиксированный, параметризованный контракт.
type namedQuery struct {
	cypher string
	params []string // обязательные параметры
}

// namedQueries — весь допустимый набор запросов для query_graph.
var namedQueries = map[string]namedQuery{
	"stats": {
		cypher: `MATCH (n) RETURN labels(n)[0] AS label, count(*) AS count
		         ORDER BY count DESC LIMIT $limit`,
	},
	"subdomains": {
		cypher: `MATCH (:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
		         RETURN s.name AS subdomain, s.source AS source
		         ORDER BY s.name LIMIT $limit`,
		params: []string{"domain"},
	},
	"resolutions": {
		cypher: `MATCH (:Subdomain {name: $host})-[:RESOLVES_TO]->(i:IP)
		         RETURN i.addr AS ip ORDER BY i.addr LIMIT $limit`,
		params: []string{"host"},
	},
	"services": {
		cypher: `MATCH (:Subdomain {name: $host})-[:RUNS]->(svc:Service)
		         RETURN svc.url AS url, svc.status_code AS status,
		                svc.title AS title, svc.webserver AS webserver, svc.tech AS tech
		         ORDER BY svc.url LIMIT $limit`,
		params: []string{"host"},
	},
	"ports": {
		cypher: `MATCH (:IP {addr: $ip})-[:HAS_PORT]->(p:Port)
		         RETURN p.number AS port, p.proto AS proto, p.service AS service
		         ORDER BY p.number LIMIT $limit`,
		params: []string{"ip"},
	},
	"findings": {
		cypher: `MATCH (svc:Service)-[:HAS_FINDING]->(f:Finding)
		         RETURN f.type AS type, f.severity AS severity, f.status AS status,
		                f.service_url AS service_url, f.evidence AS evidence
		         ORDER BY f.severity LIMIT $limit`,
	},
	"findings_by_severity": {
		cypher: `MATCH (svc:Service)-[:HAS_FINDING]->(f:Finding {severity: $severity})
		         RETURN f.type AS type, f.severity AS severity, f.status AS status,
		                f.service_url AS service_url, f.evidence AS evidence
		         ORDER BY f.service_url LIMIT $limit`,
		params: []string{"severity"},
	},
}

// QueryNames возвращает имена доступных запросов (для get_scope / документации).
func QueryNames() map[string][]string {
	out := make(map[string][]string, len(namedQueries))
	for name, q := range namedQueries {
		out[name] = q.params
	}
	return out
}

// RunNamedQuery выполняет именованный запрос с проверкой имени и обязательных
// параметров. Возвращает строки как срез map (готово к JSON).
func (s *Store) RunNamedQuery(ctx context.Context, name string, params map[string]any) ([]map[string]any, error) {
	q, ok := namedQueries[name]
	if !ok {
		return nil, fmt.Errorf("неизвестный запрос %q", name)
	}

	bind := map[string]any{"limit": int64(queryLimit)}
	for _, p := range q.params {
		v, ok := params[p]
		if !ok {
			return nil, fmt.Errorf("запрос %q требует параметр %q", name, p)
		}
		if sv, isStr := v.(string); isStr && sv == "" {
			return nil, fmt.Errorf("параметр %q не должен быть пустым", p)
		}
		bind[p] = v
	}

	sess := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer sess.Close(ctx)

	out, err := sess.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q.cypher, bind)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		rows := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			rows = append(rows, r.AsMap())
		}
		return rows, nil
	})
	if err != nil {
		return nil, err
	}
	return out.([]map[string]any), nil
}

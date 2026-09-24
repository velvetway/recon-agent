package graph

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/velvet1way/recon-agent/internal/cwe"
)

// cweBatch — сколько строк отправлять в одном UNWIND.
const cweBatch = 500

// CWELoadStats — итог загрузки каталога.
type CWELoadStats struct {
	Nodes int
	Edges int
}

// LoadCWECatalog загружает каталог слабостей в граф: узлы (:CWE) и рёбра
// (:CWE)-[:CHILD_OF]->(:CWE) из иерархии Research Concepts.
//
// Загрузка идемпотентна и выполняется одной транзакцией: старые рёбра
// CHILD_OF между узлами CWE удаляются и строятся заново, так что при смене
// версии каталога в графе не остаётся устаревшей иерархии. Узлы, которых нет
// в новом каталоге, не удаляются (на них могут ссылаться находки) — их можно
// найти по устаревшему свойству catalog_version.
func (s *Store) LoadCWECatalog(ctx context.Context, cat *cwe.Catalog) (CWELoadStats, error) {
	nodes, edges := cweRows(cat)
	err := s.write(ctx, func(tx neo4j.ManagedTransaction) error {
		if _, err := tx.Run(ctx, `MATCH (:CWE)-[r:CHILD_OF]->(:CWE) DELETE r`, nil); err != nil {
			return fmt.Errorf("очистка иерархии CWE: %w", err)
		}
		for i := 0; i < len(nodes); i += cweBatch {
			_, err := tx.Run(ctx, `
				UNWIND $rows AS r
				MERGE (c:CWE {id: r.id})
				SET c += r, c.catalog_version = $version
			`, map[string]any{"rows": nodes[i:min(i+cweBatch, len(nodes))], "version": cat.Version})
			if err != nil {
				return fmt.Errorf("запись узлов CWE: %w", err)
			}
		}
		for i := 0; i < len(edges); i += cweBatch {
			_, err := tx.Run(ctx, `
				UNWIND $rows AS e
				MATCH (c:CWE {id: e.child}), (p:CWE {id: e.parent})
				MERGE (c)-[:CHILD_OF]->(p)
			`, map[string]any{"rows": edges[i:min(i+cweBatch, len(edges))]})
			if err != nil {
				return fmt.Errorf("запись иерархии CWE: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return CWELoadStats{}, err
	}
	return CWELoadStats{Nodes: len(nodes), Edges: len(edges)}, nil
}

// cweRows превращает каталог в параметры для Cypher. В граф идут только поля,
// по которым удобно искать и связывать; полный текст записи остаётся в
// каталоге и атласе.
func cweRows(cat *cwe.Catalog) (nodes, edges []map[string]any) {
	for _, w := range cat.All() {
		capec := w.CAPEC
		if capec == nil {
			capec = []string{} // Neo4j не хранит null в списочных свойствах
		}
		nodes = append(nodes, map[string]any{
			"id":          w.ID,
			"name":        w.Name,
			"name_ru":     w.NameRU,
			"abstraction": w.Abstraction,
			"status":      w.Status,
			"top25_rank":  int64(w.Top25Rank),
			"likelihood":  w.Likelihood,
			"capec":       capec,
		})
		for _, p := range w.Parents() {
			if _, ok := cat.Get(p); !ok {
				continue // ребро на запись вне каталога не строим
			}
			edges = append(edges, map[string]any{"child": w.ID, "parent": p})
		}
	}
	return nodes, edges
}

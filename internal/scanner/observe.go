package scanner

import (
	"context"

	"github.com/velvet1way/recon-agent/internal/graph"
)

// observe записывает наблюдение прогона. Ошибка записи не проваливает задачу —
// типизированные узлы (Subdomain, IP, Service, Port) уже сохранены, а
// наблюдение лишь дублирует факт в единый вид для архива; логируем и идём
// дальше, чтобы одна сбойная запись не рвала весь скан.
func (s *Scanner) observe(ctx context.Context, asset, tool, kind, value, evidence string) {
	err := s.store.AddObservation(ctx, graph.Observation{
		RunID: s.runID, Asset: asset, Tool: tool, Kind: kind, Value: value, Evidence: evidence,
	})
	if err != nil {
		s.log.Error("запись наблюдения", "asset", asset, "kind", kind, "err", err)
	}
}

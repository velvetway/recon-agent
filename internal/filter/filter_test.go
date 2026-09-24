package filter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/graph"
)

func ob(asset, kind, value, ev string) graph.Observation {
	return graph.Observation{Asset: asset, Kind: kind, Value: value, Evidence: ev}
}

func values(obs []graph.Observation) []string {
	out := make([]string, len(obs))
	for i, o := range obs {
		out[i] = o.Asset + "/" + o.Kind + "/" + o.Value
	}
	return out
}

func TestSanitize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		hits []string
		gone string // подстрока, которой не должно остаться
	}{
		{"jwt", "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456", []string{"jwt"}, "eyJzdWIi"},
		{"aws", "key AKIAIOSFODNN7EXAMPLE here", []string{"aws_key"}, "AKIAIOSFODNN7EXAMPLE"},
		{"github", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", []string{"github_token"}, "ghp_ABCDEF"},
		{"bearer", "Authorization: Bearer abcdef0123456789ABCDEF", []string{"bearer"}, "abcdef0123456789ABCDEF"},
		{"kv", "config api_key=SuperSecretValue123", []string{"secret_kv"}, "SuperSecretValue123"},
		{"url", "db at postgres://admin:hunter2@db.internal:5432", []string{"url_creds"}, "hunter2"},
		{"clean", "just nginx 1.18 on 203.0.113.5", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hits := Sanitize(c.in)
			if !reflect.DeepEqual(hits, c.hits) {
				t.Errorf("hits = %v, want %v", hits, c.hits)
			}
			if c.gone != "" && strings.Contains(got, c.gone) {
				t.Errorf("секрет не вырезан, осталось %q в %q", c.gone, got)
			}
			if c.name == "url" && !strings.Contains(got, "db.internal") {
				t.Errorf("url_creds не должен прятать хост: %q", got)
			}
		})
	}
}

func TestApplyDedupAndParking(t *testing.T) {
	f := New(Default())
	in := []graph.Observation{
		ob("a.example.com", "tech", "nginx", "x"),
		ob("a.example.com", "tech", "nginx", "x"), // дубль
		ob("a.example.com", "http_service", "https://a.example.com", "200 OK"),
		ob("park.example.com", "http_service", "https://park.example.com", "200 This domain is for sale"),
		ob("park.example.com", "tech", "apache", "x"),
	}
	kept, rep := f.Apply(in)
	if rep.Deduped != 1 {
		t.Errorf("Deduped = %d, want 1", rep.Deduped)
	}
	if !reflect.DeepEqual(rep.DroppedPark, []string{"park.example.com"}) {
		t.Errorf("DroppedPark = %v", rep.DroppedPark)
	}
	// park.* выброшен целиком (обе записи), дубль nginx схлопнут → 2 записи.
	if got := values(kept); !reflect.DeepEqual(got, []string{"a.example.com/tech/nginx", "a.example.com/http_service/https://a.example.com"}) {
		t.Errorf("kept = %v", got)
	}
}

func TestApplyCDNTagNotDropped(t *testing.T) {
	f := New(Default())
	in := []graph.Observation{
		ob("cf.example.com", "tech", "Cloudflare", "https://cf.example.com"),
		ob("cf.example.com", "http_service", "https://cf.example.com", "200 OK"),
	}
	kept, rep := f.Apply(in)
	if !reflect.DeepEqual(rep.CDN, []string{"cf.example.com"}) {
		t.Errorf("CDN = %v", rep.CDN)
	}
	if len(rep.DroppedCDN) != 0 {
		t.Errorf("по умолчанию CDN не отбрасывается, а DroppedCDN = %v", rep.DroppedCDN)
	}
	if len(kept) != 2 {
		t.Errorf("kept = %d, want 2 (CDN помечен, не удалён)", len(kept))
	}
}

func TestApplyDropCDN(t *testing.T) {
	cfg := Default()
	cfg.DropCDN = true
	f := New(cfg)
	in := []graph.Observation{ob("cf.example.com", "tech", "akamai", "x")}
	kept, rep := f.Apply(in)
	if len(kept) != 0 || !reflect.DeepEqual(rep.DroppedCDN, []string{"cf.example.com"}) {
		t.Errorf("kept=%v DroppedCDN=%v", values(kept), rep.DroppedCDN)
	}
}

func TestApplyCaps(t *testing.T) {
	cfg := Config{MaxPerKind: 2, MaxPerAsset: 3}
	f := New(cfg)
	var in []graph.Observation
	for _, v := range []string{"a", "b", "c", "d"} { // 4 tech
		in = append(in, ob("h.example.com", "tech", v, ""))
	}
	in = append(in, ob("h.example.com", "open_port", "80/tcp", ""))
	in = append(in, ob("h.example.com", "open_port", "443/tcp", ""))
	kept, rep := f.Apply(in)
	// tech: max 2 из 4 (2 capped). Затем per_asset=3 достигнут на первом
	// open_port → второй capped. Итого kept = 3, capped = 3.
	if rep.Kept != 3 || rep.Capped != 3 {
		t.Errorf("Kept=%d Capped=%d, want 3/3 (%v)", rep.Kept, rep.Capped, values(kept))
	}
}

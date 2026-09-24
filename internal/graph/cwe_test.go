package graph

import (
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/cwe"
)

func TestCWERows(t *testing.T) {
	cat, err := cwe.Parse(strings.NewReader(`{"version":"4.14","weaknesses":[
		{"id":"707","name":"Pillar","abstraction":"Pillar","relations":{}},
		{"id":"74","name":"Injection","abstraction":"Class","relations":{"ChildOf":["707"]},"capec":["10"]},
		{"id":"79","name":"XSS","name_ru":"XSS ru","abstraction":"Base","top25_rank":2,
		 "relations":{"ChildOf":["74","999"],"PeerOf":["74"]}}
	]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	nodes, edges := cweRows(cat)
	if len(nodes) != 3 {
		t.Fatalf("узлов %d, want 3", len(nodes))
	}
	// PeerOf в иерархию не попадает, ребро на отсутствующий 999 отбрасывается.
	want := map[string]string{"74": "707", "79": "74"}
	if len(edges) != len(want) {
		t.Fatalf("рёбра %v, want %v", edges, want)
	}
	for _, e := range edges {
		if want[e["child"].(string)] != e["parent"] {
			t.Errorf("лишнее ребро %v", e)
		}
	}
	for _, n := range nodes {
		if n["capec"] == nil {
			t.Errorf("CWE-%s: capec = nil, Neo4j ждёт список", n["id"])
		}
		if n["id"] == "79" && (n["top25_rank"] != int64(2) || n["name_ru"] != "XSS ru") {
			t.Errorf("CWE-79 = %v", n)
		}
	}
}

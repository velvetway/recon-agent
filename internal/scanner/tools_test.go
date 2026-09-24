package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/queue"
)

func TestTaskURL(t *testing.T) {
	if got := taskURL(queue.Task{Target: "h", URL: "https://h/x"}); got != "https://h/x" {
		t.Errorf("с URL: %q", got)
	}
	if got := taskURL(queue.Task{Target: "h"}); got != "https://h" {
		t.Errorf("без URL: %q", got)
	}
}

func TestKatanaParse(t *testing.T) {
	// Поле url в новых версиях, request.endpoint в старых — поддержаны оба.
	var a katanaResult
	json.Unmarshal([]byte(`{"url":"https://a.example.com/x"}`), &a)
	if a.url() != "https://a.example.com/x" {
		t.Errorf("url: %q", a.url())
	}
	var b katanaResult
	json.Unmarshal([]byte(`{"request":{"endpoint":"https://b.example.com/y"}}`), &b)
	if b.url() != "https://b.example.com/y" {
		t.Errorf("endpoint: %q", b.url())
	}
}

func TestKatanaArgs(t *testing.T) {
	args := katanaArgs("https://h/x", Config{
		HTTPHeaders:  []Header{{"X-BugBounty", "abc"}},
		PerTargetRPS: 10,
	})
	j := strings.Join(args, " ")
	for _, want := range []string{"-u https://h/x", "-jsonl", "-H X-BugBounty: abc", "-rl 10"} {
		if !strings.Contains(j, want) {
			t.Errorf("нет %q в %v", want, args)
		}
	}
}

func TestNucleiParse(t *testing.T) {
	line := `{"template-id":"CVE-2021-1234","host":"https://h.example.com",
	  "matched-at":"https://h.example.com/path","type":"http",
	  "info":{"name":"Example RCE","severity":"critical",
	    "classification":{"cwe-id":["CWE-78","CWE-77"],"cve-id":["CVE-2021-1234"]}}}`
	var nr nucleiResult
	if err := json.Unmarshal([]byte(line), &nr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nr.asset() != "h.example.com" {
		t.Errorf("asset = %q", nr.asset())
	}
	if nr.Info.Severity != "critical" || nr.TemplateID != "CVE-2021-1234" {
		t.Errorf("nr = %+v", nr)
	}
	if len(nr.Info.Classification.CWE) != 2 || nr.Info.Classification.CWE[0] != "CWE-78" {
		t.Errorf("cwe = %v", nr.Info.Classification.CWE)
	}
	if len(nr.Info.Classification.CVE) != 1 || nr.Info.Classification.CVE[0] != "CVE-2021-1234" {
		t.Errorf("cve = %v", nr.Info.Classification.CVE)
	}
}

// Находка без классификации не должна ронять разбор.
func TestNucleiNoClassification(t *testing.T) {
	var nr nucleiResult
	if err := json.Unmarshal([]byte(`{"template-id":"tech-detect","matched-at":"https://h/","info":{"severity":"info"}}`), &nr); err != nil {
		t.Fatal(err)
	}
	if nr.asset() != "h" || len(nr.Info.Classification.CWE) != 0 {
		t.Errorf("nr = %+v", nr)
	}
}

func TestNucleiArgs(t *testing.T) {
	args := nucleiArgs("https://h", Config{PerTargetRPS: 5, HTTPHeaders: []Header{{"X-BugBounty", "z"}}})
	j := strings.Join(args, " ")
	for _, want := range []string{"-u https://h", "-jsonl", "-rl 5", "-H X-BugBounty: z"} {
		if !strings.Contains(j, want) {
			t.Errorf("нет %q в %v", want, args)
		}
	}
}

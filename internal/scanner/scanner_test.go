package scanner

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/velvet1way/recon-agent/internal/config"
	"github.com/velvet1way/recon-agent/internal/scope"
)

// TestPortScanRejectsNonIP проверяет, что port_scan не запустит nmap по
// доменному имени (даже если оно в скоупе): цель обязана быть IP.
func TestPortScanRejectsNonIP(t *testing.T) {
	sc := &config.Scope{}
	sc.InScope.Domains = []string{"*.example.com"}
	sc.InScope.Wildcards = true
	guard, err := scope.New(sc)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	s := New(guard, nil, nil, "", nil)

	err = s.PortScan(context.Background(), "api.example.com")
	if err == nil || !strings.Contains(err.Error(), "IP-адрес") {
		t.Fatalf("ожидался отказ port_scan по домену, получено: %v", err)
	}
}

func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"https://api.standoff365.com/login": "api.standoff365.com",
		"http://host:8080/x":                "host",
		"api.standoff365.com":               "api.standoff365.com",
		"https://host":                      "host",
	}
	for in, want := range cases {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNmapXML(t *testing.T) {
	const sample = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(sample), &run); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(run.Hosts))
	}
	ports := run.Hosts[0].Ports.Port
	if len(ports) != 3 {
		t.Fatalf("ports = %d, want 3", len(ports))
	}

	open := 0
	for _, p := range ports {
		if p.State.State == "open" {
			open++
		}
	}
	if open != 2 {
		t.Errorf("open ports = %d, want 2", open)
	}
	if ports[0].PortID != 80 || ports[0].Service.Name != "http" {
		t.Errorf("port[0] = %d/%s, want 80/http", ports[0].PortID, ports[0].Service.Name)
	}
}

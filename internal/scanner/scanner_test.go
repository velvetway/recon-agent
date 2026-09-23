package scanner

import (
	"encoding/xml"
	"testing"
)

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

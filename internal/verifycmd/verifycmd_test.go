package verifycmd

import (
	"strings"
	"testing"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/model"
)

func tcpFlow(dstLabels []string, dstNS, dstIP string, port int32, destNames ...string) *hubble.Flow {
	f := &hubble.Flow{
		Destination:      hubble.Endpoint{Namespace: dstNS, Labels: dstLabels},
		DestinationNames: destNames,
	}
	f.IP.Destination = dstIP
	f.L4.TCP = &struct {
		DestinationPort int32 `json:"destination_port"`
	}{DestinationPort: port}
	return f
}

func udpFlow(dstIP string, port int32) *hubble.Flow {
	f := &hubble.Flow{}
	f.IP.Destination = dstIP
	f.L4.UDP = &struct {
		DestinationPort int32 `json:"destination_port"`
	}{DestinationPort: port}
	return f
}

func TestClassifyDestinationEndpoint(t *testing.T) {
	f := tcpFlow([]string{"k8s:app.kubernetes.io/name=postgres"}, "webshop", "10.0.0.5", 5432)
	k := classifyDestination(f, nil)
	if k.kind != "endpoint" || k.dst != "k8s:app.kubernetes.io/name=postgres" || k.ns != "webshop" || k.port != 5432 || k.proto != "TCP" {
		t.Fatalf("unexpected key: %+v", k)
	}
}

func TestClassifyDestinationFqdnFromIndex(t *testing.T) {
	f := tcpFlow(nil, "", "93.184.216.34", 443)
	idx := model.NewResolveIndex()
	idx.IPToFqdns["93.184.216.34"] = &model.ResolvedFqdn{
		IP: "93.184.216.34", Fqdns: map[string]struct{}{"example.com": {}},
	}
	k := classifyDestination(f, idx)
	if k.kind != "fqdn" || k.dst != "example.com" {
		t.Fatalf("unexpected key: %+v", k)
	}
}

func TestClassifyDestinationFqdnFromFlowNames(t *testing.T) {
	f := tcpFlow(nil, "", "93.184.216.34", 443, "example.com")
	k := classifyDestination(f, nil)
	if k.kind != "fqdn" || k.dst != "example.com" {
		t.Fatalf("unexpected key: %+v", k)
	}
}

func TestClassifyDestinationCidrFallback(t *testing.T) {
	f := udpFlow("5.6.7.8", 53)
	k := classifyDestination(f, nil)
	if k.kind != "cidr" || k.dst != "5.6.7.8/32" || k.proto != "UDP" || k.port != 53 {
		t.Fatalf("unexpected key: %+v", k)
	}
}

func TestClassifyDestinationNoPortSkipped(t *testing.T) {
	f := &hubble.Flow{}
	f.IP.Destination = "5.6.7.8"
	k := classifyDestination(f, nil)
	if k.dst != "" {
		t.Fatalf("expected empty key for a flow with no L4 info, got %+v", k)
	}
}

func TestSnippetFqdn(t *testing.T) {
	lines := snippet(suggestKey{dst: "example.com", kind: "fqdn", port: 443, proto: "TCP"})
	joined := strings.Join(lines, "\n")
	for _, want := range []string{`toFQDNs:`, `matchName: "example.com"`, `port: "443"`, `protocol: TCP`} {
		if !strings.Contains(joined, want) {
			t.Errorf("snippet missing %q:\n%s", want, joined)
		}
	}
}

func TestSnippetEndpoint(t *testing.T) {
	lines := snippet(suggestKey{dst: "k8s:app.kubernetes.io/name=postgres", kind: "endpoint", ns: "webshop", port: 5432, proto: "TCP"})
	joined := strings.Join(lines, "\n")
	for _, want := range []string{`toEndpoints:`, `app.kubernetes.io/name: postgres`, `io.kubernetes.pod.namespace: webshop`} {
		if !strings.Contains(joined, want) {
			t.Errorf("snippet missing %q:\n%s", want, joined)
		}
	}
}

func TestSnippetCidr(t *testing.T) {
	lines := snippet(suggestKey{dst: "5.6.7.8/32", kind: "cidr", port: 53, proto: "UDP"})
	joined := strings.Join(lines, "\n")
	for _, want := range []string{`toCIDR:`, `5.6.7.8/32`, `protocol: UDP`} {
		if !strings.Contains(joined, want) {
			t.Errorf("snippet missing %q:\n%s", want, joined)
		}
	}
}

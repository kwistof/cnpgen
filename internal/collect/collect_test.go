package collect

import (
	"testing"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/model"
)

func flow(srcLabels, dstLabels []string, srcNS, dstNS string, port int32, proto, dstIP, typ string, reply bool) *hubble.Flow {
	f := &hubble.Flow{
		Type:        typ,
		IsReply:     reply,
		Source:      hubble.Endpoint{Namespace: srcNS, Labels: srcLabels},
		Destination: hubble.Endpoint{Namespace: dstNS, Labels: dstLabels},
	}
	f.IP.Destination = dstIP
	switch proto {
	case "TCP":
		f.L4.TCP = &struct {
			DestinationPort int32 `json:"destination_port"`
		}{port}
	case "UDP":
		f.L4.UDP = &struct {
			DestinationPort int32 `json:"destination_port"`
		}{port}
	}
	return f
}

func TestExtractEgressToApp(t *testing.T) {
	front := []string{"k8s:app.kubernetes.io/name=frontend"}
	back := []string{"k8s:app.kubernetes.io/name=backend"}
	flows := []*hubble.Flow{
		flow(front, back, "webshop", "webshop", 8080, "TCP", "", "L3_L4", false),
	}
	g := ExtractConnections(flows, "app.kubernetes.io/name=frontend", "webshop")
	b := g.Buckets()[model.Endpoint{App: "k8s:app.kubernetes.io/name=frontend", Namespace: "webshop"}]
	if b == nil {
		t.Fatal("no bucket for frontend")
	}
	key := model.AppConn{Peer: model.Endpoint{App: "k8s:app.kubernetes.io/name=backend", Namespace: "webshop"}, Port: 8080, Proto: "TCP"}
	if b.EgressApps[key] != 1 {
		t.Errorf("expected egress to backend, got %v", b.EgressApps)
	}
}

func TestExtractIgnoresSameLabelDifferentNamespace(t *testing.T) {
	front := []string{"k8s:app.kubernetes.io/name=frontend"}
	back := []string{"k8s:app.kubernetes.io/name=backend"}
	flows := []*hubble.Flow{
		// Same label, but this frontend lives in a different namespace than
		// the one we're generating a policy for: a CNP written into "webshop"
		// could never match it, so it must not be counted as "ours".
		flow(front, back, "other-ns", "webshop", 8080, "TCP", "", "L3_L4", false),
	}
	g := ExtractConnections(flows, "app.kubernetes.io/name=frontend", "webshop")
	if g.Len() != 0 {
		t.Errorf("expected no buckets for out-of-namespace match, got %d", g.Len())
	}
}

func TestExtractEgressExternal(t *testing.T) {
	front := []string{"k8s:app.kubernetes.io/name=frontend"}
	world := []string{"reserved:world"}
	flows := []*hubble.Flow{
		flow(front, world, "webshop", "", 443, "TCP", "1.2.3.4", "L3_L4", false),
	}
	g := ExtractConnections(flows, "app.kubernetes.io/name=frontend", "webshop")
	b := g.Buckets()[model.Endpoint{App: "k8s:app.kubernetes.io/name=frontend", Namespace: "webshop"}]
	if b.EgressExternal[model.ExtConn{IP: "1.2.3.4", Port: 443, Proto: "TCP"}] != 1 {
		t.Errorf("expected external egress, got %v", b.EgressExternal)
	}
}

func TestSkipReplyAndSock(t *testing.T) {
	front := []string{"k8s:app.kubernetes.io/name=frontend"}
	back := []string{"k8s:app.kubernetes.io/name=backend"}
	flows := []*hubble.Flow{
		flow(front, back, "webshop", "webshop", 8080, "TCP", "", "L3_L4", true), // reply
		flow(front, back, "webshop", "webshop", 8080, "TCP", "", "SOCK", false), // sock
	}
	g := ExtractConnections(flows, "app.kubernetes.io/name=frontend", "webshop")
	if g.Len() != 0 {
		t.Errorf("reply and SOCK flows should be ignored, got %d buckets", g.Len())
	}
}

func TestExtractIngress(t *testing.T) {
	front := []string{"k8s:app.kubernetes.io/name=frontend"}
	back := []string{"k8s:app.kubernetes.io/name=backend"}
	flows := []*hubble.Flow{
		flow(front, back, "webshop", "webshop", 8080, "TCP", "", "L3_L4", false),
	}
	// Target the backend: it should get an ingress-from-frontend entry.
	g := ExtractConnections(flows, "app.kubernetes.io/name=backend", "webshop")
	b := g.Buckets()[model.Endpoint{App: "k8s:app.kubernetes.io/name=backend", Namespace: "webshop"}]
	if b == nil {
		t.Fatal("no bucket for backend")
	}
	key := model.AppConn{Peer: model.Endpoint{App: "k8s:app.kubernetes.io/name=frontend", Namespace: "webshop"}, Port: 8080, Proto: "TCP"}
	if b.IngressApps[key] != 1 {
		t.Errorf("expected ingress from frontend, got %v", b.IngressApps)
	}
}

func TestParseLineWrapped(t *testing.T) {
	line := []byte(`{"flow":{"Type":"L3_L4","destination":{"labels":["reserved:world"]},"IP":{"destination":"1.2.3.4"}}}`)
	f, err := hubble.ParseLine(line)
	if err != nil || f == nil {
		t.Fatalf("parse failed: %v", err)
	}
	if f.DstIP() != "1.2.3.4" {
		t.Errorf("got dst IP %q", f.DstIP())
	}
}

func TestParseLineSentinel(t *testing.T) {
	// A non-flow line (e.g. Hubble ring-buffer sentinel) yields nil, nil.
	f, err := hubble.ParseLine([]byte(`{"lost_events":{"source":"OBSERVER"}}`))
	if err != nil || f != nil {
		t.Errorf("expected nil flow for sentinel, got %v %v", f, err)
	}
}

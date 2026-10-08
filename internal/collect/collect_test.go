package collect

import (
	"strings"
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

func TestExtractNamesOurPodsByTheLabel(t *testing.T) {
	// The audited pods also carry app.kubernetes.io/name=ms, shared with other
	// instances: the bucket (so the policy name and endpointSelector) must use
	// the -l label, and so must a self-connection's peer.
	ms := []string{"k8s:app.kubernetes.io/name=ms", "k8s:app.kubernetes.io/instance=adm-slowquery-1"}
	flows := []*hubble.Flow{
		flow(ms, ms, "dif", "dif", 8080, "TCP", "", "L3_L4", false),
	}
	g := ExtractConnections(flows, "app.kubernetes.io/instance=adm-slowquery-1", "dif")
	ours := model.Endpoint{App: "k8s:app.kubernetes.io/instance=adm-slowquery-1", Namespace: "dif"}
	b := g.Buckets()[ours]
	if b == nil || g.Len() != 1 {
		t.Fatalf("expected a single bucket keyed by the -l label, got %v", g.Buckets())
	}
	key := model.AppConn{Peer: ours, Port: 8080, Proto: "TCP"}
	if b.EgressApps[key] != 1 || b.IngressApps[key] != 1 {
		t.Errorf("expected self egress/ingress keyed by the -l label, got egress=%v ingress=%v", b.EgressApps, b.IngressApps)
	}
}

// Hubble ORs repeated --label filters: one stream covers every audited label.
func TestObserveCmdLabels(t *testing.T) {
	got := strings.Join(observeCmd([]string{"app=a", "app=b"}, 0, true, ""), " ")
	want := "hubble observe --output json --label app=a --label app=b --follow"
	if got != want {
		t.Errorf("observeCmd = %q, want %q", got, want)
	}
	got = strings.Join(observeCmd(nil, 10, false, ""), " ")
	want = "hubble observe --output json --last 10"
	if got != want {
		t.Errorf("observeCmd(no labels) = %q, want %q", got, want)
	}
}

func TestExtractIngressFromUnlabelledPod(t *testing.T) {
	job := []string{
		"k8s:io.kubernetes.pod.namespace=jobs",
		"k8s:batch.kubernetes.io/job-name=notify-29857686",
		"k8s:job-name=notify-29857686",
	}
	back := []string{"k8s:app.kubernetes.io/name=backend"}
	flows := []*hubble.Flow{flow(job, back, "jobs", "webshop", 8080, "TCP", "", "L3_L4", false)}
	g := ExtractConnections(flows, "app.kubernetes.io/name=backend", "webshop")
	b := g.Buckets()[model.Endpoint{App: "k8s:app.kubernetes.io/name=backend", Namespace: "webshop"}]
	if b == nil {
		t.Fatal("no bucket for backend")
	}
	// Per-run Job labels are skipped: the pod is selected by its namespace.
	key := model.AppConn{Peer: model.Endpoint{App: "k8s:io.kubernetes.pod.namespace=jobs", Namespace: "jobs"}, Port: 8080, Proto: "TCP"}
	if b.IngressApps[key] != 1 {
		t.Errorf("expected ingress from the jobs namespace, got %v", b.IngressApps)
	}
}

func TestExtractIngressFromReserved(t *testing.T) {
	back := []string{"k8s:app.kubernetes.io/name=backend"}
	label := "app.kubernetes.io/name=backend"
	ingress := flow([]string{"reserved:ingress"}, back, "", "webshop", 8080, "TCP", "", "L3_L4", false)
	world := flow([]string{"reserved:world"}, back, "", "webshop", 8080, "TCP", "", "L3_L4", false)
	unknown := flow([]string{"reserved:unknown"}, back, "", "webshop", 8080, "TCP", "", "L3_L4", false)
	// Kubelet probes: Cilium always lets the local host in.
	host := flow([]string{"reserved:host"}, back, "", "webshop", 15021, "TCP", "", "L3_L4", false)

	g := ExtractConnections([]*hubble.Flow{ingress, world, unknown, host}, label, "webshop")
	b := g.Buckets()[model.Endpoint{App: "k8s:app.kubernetes.io/name=backend", Namespace: "webshop"}]
	if b == nil {
		t.Fatal("no bucket for backend")
	}
	key := model.AppConn{Peer: model.Endpoint{App: "reserved:ingress"}, Port: 8080, Proto: "TCP"}
	if b.IngressApps[key] != 1 || len(b.IngressApps) != 1 {
		t.Errorf("expected only ingress from the ingress entity, got %v", b.IngressApps)
	}

	for f, want := range map[*hubble.Flow]string{ingress: "", world: NoIdentity, unknown: NotSelectable} {
		if got := Unusable(f, label, "webshop"); got != want {
			t.Errorf("Unusable(%v) = %q, want %q", f.Source.Labels, got, want)
		}
	}
}

package verifycmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/model"
)

const (
	label = "app.kubernetes.io/name=frontend"
	ns    = "webshop"
)

var frontend = hubble.Endpoint{Namespace: ns, Labels: []string{"k8s:app.kubernetes.io/name=frontend", "k8s:io.kubernetes.pod.namespace=webshop"}}

func tcpFlow(src, dst hubble.Endpoint, dir, dstIP string, port int32, destNames ...string) *hubble.Flow {
	f := &hubble.Flow{
		Source:           src,
		Destination:      dst,
		DestinationNames: destNames,
		TrafficDirection: dir,
		PolicyMatchType:  4,
	}
	f.IP.Source = "10.244.1.10"
	f.IP.Destination = dstIP
	f.L4.TCP = &struct {
		DestinationPort int32 `json:"destination_port"`
	}{DestinationPort: port}
	return f
}

func udpFlow(src, dst hubble.Endpoint, dstIP string, port int32) *hubble.Flow {
	f := &hubble.Flow{Source: src, Destination: dst, TrafficDirection: "EGRESS", PolicyMatchType: 4}
	f.IP.Destination = dstIP
	f.L4.UDP = &struct {
		DestinationPort int32 `json:"destination_port"`
	}{DestinationPort: port}
	return f
}

var world = hubble.Endpoint{Labels: []string{"reserved:world"}}

func testWatcher(t *testing.T, idx *model.ResolveIndex) *watcher {
	t.Helper()
	out := filepath.Join(t.TempDir(), "missing.yaml")
	return newWatcher(Config{Label: label, Namespace: ns, Out: out}, &resolver{index: idx})
}

func TestBlocked(t *testing.T) {
	cases := []struct {
		name string
		f    hubble.Flow
		want bool
	}{
		{"would be dropped (non-enforcing)", hubble.Flow{PolicyMatchType: 4, Verdict: "FORWARDED"}, true},
		{"dropped, no allow rule", hubble.Flow{Verdict: "DROPPED", DropReasonDesc: "POLICY_DENIED"}, true},
		{"dropped by explicit deny rule", hubble.Flow{Verdict: "DROPPED", DropReasonDesc: "POLICY_DENY"}, false},
		{"allowed", hubble.Flow{PolicyMatchType: 2, Verdict: "FORWARDED"}, false},
	}
	for _, c := range cases {
		if got := blocked(&c.f); got != c.want {
			t.Errorf("%s: blocked = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	backend := hubble.Endpoint{Namespace: ns, Labels: []string{"k8s:app.kubernetes.io/name=backend"}}
	apiserver := hubble.Endpoint{Labels: []string{"reserved:kube-apiserver"}}
	idx := model.NewResolveIndex()
	idx.IPToFqdns["93.184.216.34"] = &model.ResolvedFqdn{Fqdns: map[string]struct{}{"example.com": {}}}

	cases := []struct {
		name string
		f    *hubble.Flow
		want peerKey
		ok   bool
	}{
		{"egress to pod", tcpFlow(frontend, backend, "EGRESS", "10.244.1.5", 8080),
			peerKey{dir: "egress", kind: "endpoint", value: "k8s:app.kubernetes.io/name=backend", ns: ns}, true},
		{"egress fqdn from flow names", tcpFlow(frontend, world, "EGRESS", "140.82.121.6", 443, "api.github.com."),
			peerKey{dir: "egress", kind: "fqdn", value: "api.github.com"}, true},
		{"egress fqdn from cache", tcpFlow(frontend, world, "EGRESS", "93.184.216.34", 443),
			peerKey{dir: "egress", kind: "fqdn", value: "example.com"}, true},
		{"egress cidr fallback", udpFlow(frontend, world, "5.6.7.8", 123),
			peerKey{dir: "egress", kind: "cidr", value: "5.6.7.8/32"}, true},
		{"egress to entity", tcpFlow(frontend, apiserver, "EGRESS", "172.18.0.2", 6443),
			peerKey{dir: "egress", kind: "entity", value: "kube-apiserver"}, true},
		{"ingress from pod", tcpFlow(backend, frontend, "INGRESS", "10.244.1.10", 80),
			peerKey{dir: "ingress", kind: "endpoint", value: "k8s:app.kubernetes.io/name=backend", ns: ns}, true},
		{"peer's own egress to us is not our policy", tcpFlow(backend, frontend, "EGRESS", "10.244.1.10", 80),
			peerKey{}, false},
		{"same label, other namespace is not ours", tcpFlow(hubble.Endpoint{Namespace: "other", Labels: frontend.Labels[:1]}, world, "EGRESS", "5.6.7.8", 443),
			peerKey{}, false},
	}
	w := testWatcher(t, idx)
	for _, c := range cases {
		pk, _, ok := w.classify(c.f)
		if ok != c.ok || pk != c.want {
			t.Errorf("%s: got %+v ok=%v, want %+v ok=%v", c.name, pk, ok, c.want, c.ok)
		}
	}
}

func TestClassifyNoPortSkipped(t *testing.T) {
	f := &hubble.Flow{Source: frontend, Destination: world, TrafficDirection: "EGRESS", PolicyMatchType: 4}
	f.IP.Destination = "5.6.7.8"
	if _, _, ok := testWatcher(t, nil).classify(f); ok {
		t.Fatal("expected a flow with no L4 info to be skipped")
	}
}

func TestOnFlowDedupesAndWritesFile(t *testing.T) {
	kubeDNS := hubble.Endpoint{Namespace: "kube-system", Labels: []string{"k8s:k8s-app=kube-dns"}}
	w := testWatcher(t, nil)

	w.onFlow(tcpFlow(frontend, world, "EGRESS", "140.82.121.6", 443, "api.github.com"))
	w.onFlow(tcpFlow(frontend, world, "EGRESS", "140.82.121.7", 443, "api.github.com")) // same rule
	w.onFlow(tcpFlow(frontend, world, "EGRESS", "140.82.121.6", 80, "api.github.com"))  // new port, same rule
	w.onFlow(udpFlow(frontend, kubeDNS, "10.96.0.10", 53))
	reply := tcpFlow(frontend, world, "EGRESS", "1.1.1.1", 443)
	reply.IsReply = true
	w.onFlow(reply)
	allowed := tcpFlow(frontend, world, "EGRESS", "9.9.9.9", 443)
	allowed.PolicyMatchType = 2
	w.onFlow(allowed)

	if w.blocked != 4 || w.count != 3 || len(w.rules) != 2 {
		t.Fatalf("blocked=%d count=%d rules=%d, want 4/3/2", w.blocked, w.count, len(w.rules))
	}

	w.flush()
	if w.dirty {
		t.Fatal("still dirty after flush")
	}
	data, err := os.ReadFile(w.cfg.Out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Egress  []map[string]any `json:"egress"`
		Ingress []map[string]any `json:"ingress"`
	}
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		t.Fatalf("output isn't valid YAML: %v\n%s", err, data)
	}
	if len(doc.Egress) != 2 || len(doc.Ingress) != 0 {
		t.Fatalf("want 2 egress rules, got:\n%s", data)
	}
	for _, want := range []string{
		`matchName: "api.github.com"`,
		`port: "80"`, `port: "443"`,
		`k8s-app: "kube-dns"`, `io.kubernetes.pod.namespace: "kube-system"`, `matchPattern: "*"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("output missing %q:\n%s", want, data)
		}
	}
}

func TestEmptyFileWritten(t *testing.T) {
	w := testWatcher(t, nil)
	if err := w.write(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(w.cfg.Out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Nothing blocked so far") {
		t.Fatalf("unexpected empty file:\n%s", data)
	}
}

func TestRuleCap(t *testing.T) {
	w := testWatcher(t, nil)
	w.count = maxRules
	if w.add(peerKey{dir: "egress", kind: "cidr", value: "1.2.3.4/32"}, portKey{443, "TCP"}) {
		t.Fatal("expected add to refuse past maxRules")
	}
	if len(w.rules) != 0 {
		t.Fatal("rule stored past the cap")
	}
}

// TestRenderParsesAsPolicyRules checks every rule kind round-trips through a
// YAML parser into the CiliumNetworkPolicy rule shape.
func TestRenderParsesAsPolicyRules(t *testing.T) {
	w := testWatcher(t, nil)
	w.add(peerKey{dir: "egress", kind: "fqdn", value: "api.github.com"}, portKey{443, "TCP"})
	w.add(peerKey{dir: "egress", kind: "endpoint", value: "k8s:k8s-app=kube-dns", ns: "kube-system"}, portKey{53, "UDP"})
	w.add(peerKey{dir: "egress", kind: "endpoint", value: "k8s:k8s-app=kube-dns", ns: "kube-system"}, portKey{9153, "TCP"})
	w.add(peerKey{dir: "egress", kind: "entity", value: "kube-apiserver"}, portKey{6443, "TCP"})
	w.add(peerKey{dir: "egress", kind: "cidr", value: "5.6.7.8/32"}, portKey{123, "UDP"})
	w.add(peerKey{dir: "ingress", kind: "endpoint", value: "k8s:app=true", ns: ns}, portKey{8080, "TCP"})
	w.add(peerKey{dir: "ingress", kind: "entity", value: "host"}, portKey{80, "TCP"})
	w.add(peerKey{dir: "ingress", kind: "cidr", value: "1.2.3.4/32"}, portKey{80, "TCP"})

	type ports struct {
		Ports []struct {
			Port     string `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
		Rules *struct {
			DNS []struct {
				MatchPattern string `json:"matchPattern"`
			} `json:"dns"`
		} `json:"rules,omitempty"`
	}
	type rule struct {
		ToFQDNs []struct {
			MatchName string `json:"matchName"`
		} `json:"toFQDNs,omitempty"`
		ToEndpoints   []struct{ MatchLabels map[string]string } `json:"toEndpoints,omitempty"`
		FromEndpoints []struct{ MatchLabels map[string]string } `json:"fromEndpoints,omitempty"`
		ToEntities    []string                                  `json:"toEntities,omitempty"`
		FromEntities  []string                                  `json:"fromEntities,omitempty"`
		ToCIDR        []string                                  `json:"toCIDR,omitempty"`
		FromCIDR      []string                                  `json:"fromCIDR,omitempty"`
		ToPorts       []ports                                   `json:"toPorts"`
	}
	var doc struct {
		Egress  []rule `json:"egress"`
		Ingress []rule `json:"ingress"`
	}
	data := w.render()
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		t.Fatalf("output doesn't parse: %v\n%s", err, data)
	}
	if len(doc.Egress) != 4 || len(doc.Ingress) != 3 {
		t.Fatalf("got %d egress / %d ingress rules:\n%s", len(doc.Egress), len(doc.Ingress), data)
	}
	var dnsRule *rule
	for i, r := range doc.Egress {
		if len(r.ToEndpoints) > 0 {
			dnsRule = &doc.Egress[i]
		}
	}
	if dnsRule == nil || len(dnsRule.ToPorts) != 2 || dnsRule.ToPorts[0].Rules == nil ||
		dnsRule.ToPorts[0].Ports[0].Port != "53" || dnsRule.ToPorts[1].Rules != nil {
		t.Fatalf("kube-dns rule should split 53 (with dns rules) from other ports:\n%s", data)
	}
	var sawStringTrue bool
	for _, r := range doc.Ingress {
		if len(r.FromEndpoints) > 0 && r.FromEndpoints[0].MatchLabels["app"] == "true" {
			sawStringTrue = true
		}
	}
	if !sawStringTrue {
		t.Fatalf("label value \"true\" must stay a string:\n%s", data)
	}
}

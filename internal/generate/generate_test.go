package generate

import (
	"strings"
	"testing"

	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/settings"
)

// buildFrontend builds a policy for a frontend app that talks to a backend
// in-cluster and to two external IPs (one resolved, one not).
func buildFrontend(t *testing.T) *Policy {
	t.Helper()
	b := &model.ConnBucket{
		EgressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: "k8s:app.kubernetes.io/name=backend", Namespace: "webshop"}, Port: 8080, Proto: "TCP"}: 3,
		},
		EgressExternal: map[model.ExtConn]int{
			{IP: "93.184.216.34", Port: 443, Proto: "TCP"}: 2, // resolved -> example.com
			{IP: "5.6.7.8", Port: 443, Proto: "TCP"}:       1, // unresolved -> toCIDR
		},
		IngressApps: map[model.AppConn]int{},
	}
	idx := model.NewResolveIndex()
	idx.IPToFqdns["93.184.216.34"] = &model.ResolvedFqdn{
		IP: "93.184.216.34", Fqdns: map[string]struct{}{"example.com": {}}, Source: "fqdn-cache",
	}
	p := BuildPolicy("k8s:app.kubernetes.io/name=frontend", "webshop", b, idx, settings.Settings{}, false, true, nil)
	if p == nil {
		t.Fatal("expected a policy, got nil")
	}
	return p
}

func TestBuildPolicyShape(t *testing.T) {
	y := buildFrontend(t).YAML()

	mustContain := []string{
		"kind: CiliumNetworkPolicy",
		"enableDefaultDeny:",
		"ingress: false",
		"egress: false",
		ManagedByLabel + ": " + ManagedByValue,
		"app.kubernetes.io/name: frontend", // endpointSelector
		"toEndpoints:",                     // backend
		"matchName: example.com",           // resolved FQDN
		"toCIDR:",                          // unresolved
		"- 5.6.7.8/32",
		"kube-apiserver",    // boilerplate
		"k8s-app: kube-dns", // DNS visibility
	}
	for _, s := range mustContain {
		if !strings.Contains(y, s) {
			t.Errorf("policy YAML missing %q:\n%s", s, y)
		}
	}
}

func TestPortsAreQuotedStrings(t *testing.T) {
	// The CNP CRD requires port to be a string, not a bare int.
	y := buildFrontend(t).YAML()
	if !strings.Contains(y, `port: "8080"`) {
		t.Errorf("expected quoted port 8080, got:\n%s", y)
	}
	if strings.Contains(y, "port: 8080") && !strings.Contains(y, `port: "8080"`) {
		t.Errorf("port must be quoted:\n%s", y)
	}
}

func TestPruneTempDNSKeepsWhenFQDNsPresent(t *testing.T) {
	p := buildFrontend(t)
	// Has FQDNs, so pruning must be a no-op and the DNS rule stays.
	if p.PruneTempDNS() {
		t.Error("PruneTempDNS should not remove DNS visibility when toFQDNs present")
	}
	if !strings.Contains(p.YAML(), "k8s-app: kube-dns") {
		t.Error("DNS rule should remain")
	}
}

func TestPruneTempDNSRemovesWhenUnused(t *testing.T) {
	// A backend that only talks in-cluster: no FQDNs -> temp DNS should prune.
	b := &model.ConnBucket{
		EgressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: "k8s:app.kubernetes.io/name=db", Namespace: "webshop"}, Port: 3306, Proto: "TCP"}: 1,
		},
		EgressExternal: map[model.ExtConn]int{},
		IngressApps:    map[model.AppConn]int{},
	}
	p := BuildPolicy("k8s:app.kubernetes.io/name=backend", "webshop", b, model.NewResolveIndex(),
		settings.Settings{}, false, true, nil)
	if !strings.Contains(p.YAML(), "k8s-app: kube-dns") {
		t.Fatal("temp DNS should be present before prune")
	}
	if !p.PruneTempDNS() {
		t.Error("expected temp DNS to be pruned")
	}
	if strings.Contains(p.YAML(), "k8s-app: kube-dns") {
		t.Error("DNS rule should be gone after prune")
	}
}

func TestReservedAppNoPolicy(t *testing.T) {
	b := &model.ConnBucket{
		EgressApps: map[model.AppConn]int{}, EgressExternal: map[model.ExtConn]int{}, IngressApps: map[model.AppConn]int{},
	}
	if p := BuildPolicy("reserved:world", "webshop", b, model.NewResolveIndex(), settings.Settings{}, false, true, nil); p != nil {
		t.Error("reserved identity should not yield a policy")
	}
}

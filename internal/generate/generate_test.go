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
		"k8s-app: kube-dns", // DNS visibility
	}
	for _, s := range mustContain {
		if !strings.Contains(y, s) {
			t.Errorf("policy YAML missing %q:\n%s", s, y)
		}
	}
	// No API server traffic was observed, so no rule for it.
	if strings.Contains(y, "kube-apiserver") {
		t.Errorf("unobserved kube-apiserver egress must not be allowed:\n%s", y)
	}
}

func TestObservedAPIServerIsAllowed(t *testing.T) {
	b := &model.ConnBucket{
		EgressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: "reserved:kube-apiserver"}, Port: 6443, Proto: "TCP"}: 1,
		},
		EgressExternal: map[model.ExtConn]int{},
		IngressApps:    map[model.AppConn]int{},
	}
	p := BuildPolicy("k8s:app.kubernetes.io/name=operator", "webshop", b, model.NewResolveIndex(), settings.Settings{}, false, true, nil)
	if p == nil {
		t.Fatal("expected a policy, got nil")
	}
	y := p.YAML()
	for _, s := range []string{"- kube-apiserver", `port: "6443"`} {
		if !strings.Contains(y, s) {
			t.Errorf("policy YAML missing %q:\n%s", s, y)
		}
	}
	if strings.Contains(y, `port: "443"`) {
		t.Errorf("only the observed port should be allowed:\n%s", y)
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

func TestNodeEntitiesAreAllowed(t *testing.T) {
	b := &model.ConnBucket{
		EgressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: "reserved:host"}, Port: 4318, Proto: "TCP"}:        1,
			{Peer: model.Endpoint{App: "reserved:remote-node"}, Port: 4318, Proto: "TCP"}: 1,
			// No identity: not a Cilium entity, so no rule.
			{Peer: model.Endpoint{App: "reserved:unknown"}}: 1,
		},
		EgressExternal: map[model.ExtConn]int{},
		IngressApps:    map[model.AppConn]int{},
	}
	p := BuildPolicy("k8s:app.kubernetes.io/name=otelapp", "webshop", b, model.NewResolveIndex(), settings.Settings{}, false, true, nil)
	if p == nil {
		t.Fatal("expected a policy, got nil")
	}
	y := p.YAML()
	for _, s := range []string{"- host", "- remote-node", `port: "4318"`} {
		if !strings.Contains(y, s) {
			t.Errorf("policy YAML missing %q:\n%s", s, y)
		}
	}
	if strings.Contains(y, "unknown") {
		t.Errorf("reserved:unknown must not become an entity rule:\n%s", y)
	}
}

func TestIngressFromEntitiesIsAllowed(t *testing.T) {
	b := &model.ConnBucket{
		EgressApps:     map[model.AppConn]int{},
		EgressExternal: map[model.ExtConn]int{},
		IngressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: "reserved:ingress"}, Port: 8080, Proto: "TCP"}: 1,
			// An unlabelled pod, selected by its namespace.
			{Peer: model.Endpoint{App: "k8s:io.kubernetes.pod.namespace=jobs", Namespace: "jobs"}, Port: 8080, Proto: "TCP"}: 1,
		},
	}
	p := BuildPolicy("k8s:app.kubernetes.io/name=backend", "webshop", b, model.NewResolveIndex(), settings.Settings{}, false, true, nil)
	if p == nil {
		t.Fatal("expected a policy, got nil")
	}
	y := p.YAML()
	for _, s := range []string{"fromEntities:", "- ingress", "fromEndpoints:", "io.kubernetes.pod.namespace: jobs", `port: "8080"`} {
		if !strings.Contains(y, s) {
			t.Errorf("policy YAML missing %q:\n%s", s, y)
		}
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

func TestBootstrapDNSPolicyNameIsPerLabel(t *testing.T) {
	a := BootstrapDNSPolicyName("app.kubernetes.io/name=frontend")
	b := BootstrapDNSPolicyName("app.kubernetes.io/name=backend")
	if a != "cnpgen-bootstrap-dns-app.kubernetes.io-name-frontend" {
		t.Errorf("unexpected name %q", a)
	}
	if a == b {
		t.Errorf("two labels got the same name %q", a)
	}
	if got := BootstrapDNSPolicyName("App=My_App"); got != "cnpgen-bootstrap-dns-app-my-app" {
		t.Errorf("unexpected name %q", got)
	}
}

func TestPeersWithSamePortsShareARule(t *testing.T) {
	app := func(name string) string { return "k8s:app.kubernetes.io/name=" + name }
	b := &model.ConnBucket{
		IngressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: app("gateway"), Namespace: "istio"}, Port: 8080, Proto: "TCP"}: 1,
			{Peer: model.Endpoint{App: app("back"), Namespace: "webshop"}, Port: 8080, Proto: "TCP"}:  1,
			{Peer: model.Endpoint{App: app("ms"), Namespace: "api"}, Port: 8080, Proto: "TCP"}:        1,
			{Peer: model.Endpoint{App: app("ms"), Namespace: "api"}, Port: 9080, Proto: "TCP"}:        1,
			{Peer: model.Endpoint{App: app("ms"), Namespace: "bff"}, Port: 9080, Proto: "TCP"}:        1,
			{Peer: model.Endpoint{App: app("ms"), Namespace: "bff"}, Port: 8080, Proto: "TCP"}:        1,
		},
		EgressApps: map[model.AppConn]int{
			{Peer: model.Endpoint{App: "k8s:k8s-app=kube-dns", Namespace: "kube-system"}, Port: 53, Proto: "UDP"}: 1,
			{Peer: model.Endpoint{App: app("other-dns"), Namespace: "dns"}, Port: 53, Proto: "UDP"}:               1,
			{Peer: model.Endpoint{App: app("db"), Namespace: "data"}, Port: 5432, Proto: "TCP"}:                   1,
			{Peer: model.Endpoint{App: app("cache"), Namespace: "data"}, Port: 5432, Proto: "TCP"}:                1,
		},
		EgressExternal: map[model.ExtConn]int{},
	}
	p := BuildPolicy(app("api"), "api", b, model.NewResolveIndex(), settings.Settings{}, false, true, nil)
	plain := p.Object()["spec"].(map[string]any)

	countSelectors := func(dir, field string) []int {
		var counts []int
		for _, r := range plain[dir].([]any) {
			if sels, ok := r.(map[string]any)[field]; ok {
				counts = append(counts, len(sels.([]any)))
			}
		}
		return counts
	}
	// Ingress: {gateway, back} on 8080, {ms@api, ms@bff} on 8080+9080.
	if got := countSelectors("ingress", "fromEndpoints"); len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Errorf("ingress selectors per rule = %v, want [2 2]:\n%s", got, p.YAML())
	}
	// Egress: {cache, db} on 5432, kube-dns alone, other-dns alone (it would
	// share 53/UDP with kube-dns, but kube-dns is never merged).
	if got := countSelectors("egress", "toEndpoints"); len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 1 {
		t.Errorf("egress selectors per rule = %v, want [2 1 1]:\n%s", got, p.YAML())
	}
	if !strings.Contains(p.YAML(), "matchPattern: '*'") && !strings.Contains(p.YAML(), `matchPattern: "*"`) {
		t.Errorf("DNS visibility should be merged into the kube-dns rule:\n%s", p.YAML())
	}
}

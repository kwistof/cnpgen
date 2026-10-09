package policyindex

import (
	"context"
	"errors"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/kwistof/cnpgen/internal/hubble"
)

func obj(t *testing.T, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func ep(identity uint32, ns string, lbls ...string) hubble.Endpoint {
	if ns != "" {
		lbls = append(lbls, "k8s:io.kubernetes.pod.namespace="+ns)
	}
	return hubble.Endpoint{Identity: identity, Namespace: ns, Labels: lbls}
}

func TestSelectorMatching(t *testing.T) {
	frontend := ep(0, "webshop", "k8s:app.kubernetes.io/name=frontend", "k8s:tier=web")
	cases := []struct {
		name string
		sel  string
		want bool
	}{
		{"empty selects all", `{}`, true},
		{"plain key", `{matchLabels: {app.kubernetes.io/name: frontend}}`, true},
		{"k8s source", `{matchLabels: {"k8s:app.kubernetes.io/name": frontend}}`, true},
		{"any source", `{matchLabels: {"any:tier": web}}`, true},
		{"other source", `{matchLabels: {"container:tier": web}}`, false},
		{"wrong value", `{matchLabels: {tier: db}}`, false},
		{"In", `{matchExpressions: [{key: tier, operator: In, values: [db, web]}]}`, true},
		{"NotIn", `{matchExpressions: [{key: tier, operator: NotIn, values: [web]}]}`, false},
		{"NotIn absent key", `{matchExpressions: [{key: env, operator: NotIn, values: [prod]}]}`, true},
		{"Exists", `{matchExpressions: [{key: tier, operator: Exists}]}`, true},
		{"DoesNotExist", `{matchExpressions: [{key: tier, operator: DoesNotExist}]}`, false},
		{"all terms must match", `{matchLabels: {tier: web, app.kubernetes.io/name: backend}}`, false},
	}
	for _, c := range cases {
		sel, err := parseSelector(obj(t, c.sel))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := sel.matches(parseEndpoint(frontend)); got != c.want {
			t.Errorf("%s: matches = %v, want %v", c.name, got, c.want)
		}
	}
}

const frontendCNP = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: frontend, namespace: webshop, uid: u1, resourceVersion: "1"}
spec:
  endpointSelector: {matchLabels: {app.kubernetes.io/name: frontend}}
  egress:
  - toEndpoints: [{matchLabels: {app.kubernetes.io/name: backend}}]
`

func TestCNPOnlySelectsItsNamespace(t *testing.T) {
	p, ok := Parse(obj(t, frontendCNP))
	if !ok {
		t.Fatal("not parsed")
	}
	ix := New([]*Policy{p})
	if got := ix.Match(ep(1, "webshop", "k8s:app.kubernetes.io/name=frontend"), Egress).Policies; len(got) != 1 {
		t.Fatalf("same namespace: got %d policies", len(got))
	}
	if got := ix.Match(ep(2, "other", "k8s:app.kubernetes.io/name=frontend"), Egress).Policies; len(got) != 0 {
		t.Fatalf("other namespace: got %d policies", len(got))
	}
	// Namespace taken from the top-level field when the label is missing.
	noLabel := hubble.Endpoint{Identity: 3, Namespace: "webshop", Labels: []string{"k8s:app.kubernetes.io/name=frontend"}}
	if got := ix.Match(noLabel, Egress).Policies; len(got) != 1 {
		t.Fatalf("namespace field fallback: got %d policies", len(got))
	}
}

func TestClusterwideSelectsEveryNamespace(t *testing.T) {
	p, ok := Parse(obj(t, `
kind: CiliumClusterwideNetworkPolicy
metadata: {name: baseline}
spec:
  endpointSelector: {}
  egress: [{toEntities: [kube-apiserver]}]
`))
	if !ok || !p.Ref.Clusterwide() {
		t.Fatalf("parsed=%v ref=%+v", ok, p.Ref)
	}
	if got := New([]*Policy{p}).Match(ep(1, "anything", "k8s:app=x"), Egress).Policies; len(got) != 1 {
		t.Fatalf("got %d policies", len(got))
	}
}

func TestHostPolicySkipped(t *testing.T) {
	if _, ok := Parse(obj(t, `
kind: CiliumClusterwideNetworkPolicy
metadata: {name: host}
spec:
  nodeSelector: {}
  ingress: [{fromEntities: [cluster]}]
`)); ok {
		t.Fatal("nodeSelector-only policy should select no pod")
	}
}

func TestDirectionCoverage(t *testing.T) {
	egressOnly, _ := Parse(obj(t, frontendCNP))
	ingressOnly, _ := Parse(obj(t, `
metadata: {name: frontend-ingress, namespace: webshop}
spec:
  endpointSelector: {matchLabels: {app.kubernetes.io/name: frontend}}
  ingress: [{fromEntities: [cluster]}]
`))
	ix := New([]*Policy{egressOnly, ingressOnly})
	fe := ep(1, "webshop", "k8s:app.kubernetes.io/name=frontend")
	if got := ix.Match(fe, Egress).Policies; len(got) != 1 || got[0].Ref.Name != "frontend" {
		t.Fatalf("egress: got %v", refs(got))
	}
	if got := ix.Match(fe, Ingress).Policies; len(got) != 1 || got[0].Ref.Name != "frontend-ingress" {
		t.Fatalf("ingress: got %v", refs(got))
	}

	// No selecting policy covers ingress: fall back to every selecting one.
	ix = New([]*Policy{egressOnly})
	if got := ix.Match(fe, Ingress).Policies; len(got) != 1 {
		t.Fatalf("fallback: got %v", refs(got))
	}
}

func TestAllowAll(t *testing.T) {
	cases := []struct {
		name string
		rule string
		want bool
	}{
		{"entity all", `{toEntities: [all]}`, true},
		{"entity all with ports", `{toEntities: [all], toPorts: [{ports: [{port: "53"}]}]}`, false},
		{"empty rule allows nothing", `{}`, false},
		{"empty endpoint selector is namespace-scoped", `{toEndpoints: [{}]}`, false},
		{"world", `{toEntities: [world]}`, false},
	}
	for _, c := range cases {
		p, _ := Parse(obj(t, `
metadata: {name: p, namespace: probe}
spec:
  endpointSelector: {}
  egress: [`+c.rule+`]
`))
		m := New([]*Policy{p}).Match(ep(1, "probe", "k8s:app=x"), Egress)
		if m.AllowAll != c.want {
			t.Errorf("%s: AllowAll = %v, want %v", c.name, m.AllowAll, c.want)
		}
		if New([]*Policy{p}).Match(ep(1, "probe", "k8s:app=x"), Ingress).AllowAll {
			t.Errorf("%s: egress rule made ingress allow-all", c.name)
		}
	}
}

func TestSpecsList(t *testing.T) {
	p, ok := Parse(obj(t, `
metadata: {name: multi, namespace: ns}
specs:
- endpointSelector: {matchLabels: {app: a}}
  egress: [{toEntities: [all]}]
- endpointSelector: {matchLabels: {app: b}}
  ingress: [{fromEntities: [cluster]}]
`))
	if !ok {
		t.Fatal("not parsed")
	}
	ix := New([]*Policy{p})
	if m := ix.Match(ep(1, "ns", "k8s:app=a"), Egress); !m.AllowAll {
		t.Error("spec a's allow-all not seen")
	}
	if m := ix.Match(ep(2, "ns", "k8s:app=b"), Egress); m.AllowAll {
		t.Error("spec a's allow-all leaked to b")
	}
}

func TestPick(t *testing.T) {
	mk := func(name, label string) *Policy {
		return &Policy{Ref: Ref{Namespace: "webshop", Name: name}, Label: label}
	}
	broad := func(name string) *Policy {
		p := mk(name, "")
		p.Broad = true
		return p
	}
	fe := ep(1, "webshop", "k8s:app.kubernetes.io/name=frontend")
	cases := []struct {
		name     string
		policies []*Policy
		ex       Excludes
		want     string
		others   int
	}{
		{"none", nil, nil, "", 0},
		{"one", []*Policy{mk("a", "")}, nil, "a", 0},
		{"first by name", []*Policy{mk("a", ""), mk("b", "")}, nil, "a", 1},
		{"cnpgen label match wins", []*Policy{mk("a", ""), mk("frontend", "app.kubernetes.io/name=frontend")}, nil, "frontend", 1},
		{"bootstrap skipped", []*Policy{mk(BootstrapPrefix+"x", ""), mk("z", "")}, nil, "z", 0},
		{"bootstrap if alone", []*Policy{mk(BootstrapPrefix+"x", "")}, nil, BootstrapPrefix + "x", 0},
		{"broad after specific", []*Policy{broad("a-baseline"), mk("frontend", "")}, nil, "frontend", 1},
		{"broad after specific, whatever the names", []*Policy{broad("a-baseline"), mk("z", "")}, nil, "z", 1},
		{"broad if alone", []*Policy{broad("a-baseline")}, nil, "a-baseline", 0},
		{"broad before bootstrap", []*Policy{mk(BootstrapPrefix+"x", ""), broad("z")}, nil, "z", 0},
		{"excluded by name", []*Policy{mk("a-baseline", ""), mk("frontend", "")}, Excludes{"a-baseline"}, "frontend", 1},
		{"excluded by ns/name glob", []*Policy{mk("a-baseline", ""), mk("frontend", "")}, Excludes{"webshop/*-baseline"}, "frontend", 1},
		{"other namespace not excluded", []*Policy{mk("a-baseline", ""), mk("frontend", "")}, Excludes{"other/a-baseline"}, "a-baseline", 1},
		{"excluded after broad", []*Policy{mk("a-baseline", ""), broad("b")}, Excludes{"a-baseline"}, "b", 1},
		{"excluded if alone", []*Policy{mk("a-baseline", "")}, Excludes{"a-baseline"}, "a-baseline", 0},
	}
	for _, c := range cases {
		p, others := Pick(Match{Policies: c.policies}, fe, c.ex)
		got := ""
		if p != nil {
			got = p.Ref.Name
		}
		if got != c.want || len(others) != c.others {
			t.Errorf("%s: got %q + %d others, want %q + %d", c.name, got, len(others), c.want, c.others)
		}
	}
}

func TestBroad(t *testing.T) {
	cases := []struct {
		name, kind, specs string
		want              bool
	}{
		{"empty selector", "CiliumNetworkPolicy", `spec: {endpointSelector: {}}`, true},
		{"namespace only", "CiliumClusterwideNetworkPolicy",
			`spec: {endpointSelector: {matchLabels: {"k8s:io.kubernetes.pod.namespace": webshop}}}`, true},
		{"namespace labels only", "CiliumClusterwideNetworkPolicy",
			`spec: {endpointSelector: {matchLabels: {"k8s:io.cilium.k8s.namespace.labels.team": a}}}`, true},
		{"pod label", "CiliumNetworkPolicy", `spec: {endpointSelector: {matchLabels: {app: frontend}}}`, false},
		{"pod expression", "CiliumNetworkPolicy",
			`spec: {endpointSelector: {matchExpressions: [{key: app, operator: Exists}]}}`, false},
		{"one specific spec is enough", "CiliumNetworkPolicy",
			`specs: [{endpointSelector: {}}, {endpointSelector: {matchLabels: {app: frontend}}}]`, false},
	}
	for _, c := range cases {
		p, ok := Parse(obj(t, "kind: "+c.kind+"\nmetadata: {name: p, namespace: webshop}\n"+c.specs))
		if !ok {
			t.Fatalf("%s: not parsed", c.name)
		}
		if p.Broad != c.want {
			t.Errorf("%s: Broad = %v, want %v", c.name, p.Broad, c.want)
		}
	}
}

func TestExcludesClusterwide(t *testing.T) {
	r := Ref{Name: "baseline"}
	if !(Excludes{"clusterwide/baseline"}).Has(r) || !(Excludes{"baseline"}).Has(r) {
		t.Error("clusterwide policy not excluded")
	}
	if (Excludes{"webshop/baseline"}).Has(r) {
		t.Error("namespaced pattern excluded a clusterwide policy")
	}
	if ValidateExclude("[") == nil {
		t.Error("malformed pattern accepted")
	}
}

type fakeLister struct {
	cnps, ccnps []map[string]any
	ccnpErr     error
}

func (f *fakeLister) ListPolicies(context.Context, string) ([]map[string]any, error) {
	return f.cnps, nil
}

func (f *fakeLister) ListClusterwidePolicies(context.Context) ([]map[string]any, error) {
	return f.ccnps, f.ccnpErr
}

func TestSourceReloadsOnlyOnChange(t *testing.T) {
	l := &fakeLister{cnps: []map[string]any{obj(t, frontendCNP)}, ccnpErr: errors.New("forbidden")}
	s := NewSource(l, "")
	ix, warn, err := s.Load(context.Background())
	if err != nil || ix == nil || ix.Len() != 1 || warn == "" {
		t.Fatalf("first load: ix=%v warn=%q err=%v", ix, warn, err)
	}
	ix, warn, err = s.Load(context.Background())
	if err != nil || ix != nil || warn != "" {
		t.Fatalf("unchanged reload: ix=%v warn=%q err=%v (want nil index, warning only once)", ix, warn, err)
	}
	l.cnps[0]["metadata"].(map[string]any)["resourceVersion"] = "2"
	if ix, _, _ = s.Load(context.Background()); ix == nil {
		t.Fatal("changed policy not reloaded")
	}
}

func refs(ps []*Policy) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Ref.String())
	}
	return out
}

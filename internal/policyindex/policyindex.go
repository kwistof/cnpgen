// Package policyindex answers "which deployed policies apply to this
// endpoint, in this direction?" for cnpgen verify. It reads
// CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy objects, evaluates
// their endpointSelectors against the Cilium labels a Hubble flow carries,
// and picks the policy a missing rule should be added to.
//
// It also detects allow-all rules (toEntities/fromEntities "all" with no
// port restriction): Cilium reports traffic matched by those with
// policy_match_type 4, the same value as traffic only let through because
// enableDefaultDeny is off, so verify has to tell the two apart from the
// policy itself.
package policyindex

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/labels"
)

// Dir is a traffic direction, as enforced at the selected endpoint.
type Dir int

const (
	Ingress Dir = iota
	Egress
)

// String returns "ingress" or "egress".
func (d Dir) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

// Ref identifies one policy. Namespace is "" for a clusterwide policy.
type Ref struct {
	Namespace string
	Name      string
}

// Clusterwide reports whether r is a CiliumClusterwideNetworkPolicy.
func (r Ref) Clusterwide() bool { return r.Namespace == "" }

// String renders "namespace/name", or "clusterwide/name".
func (r Ref) String() string {
	if r.Clusterwide() {
		return "clusterwide/" + r.Name
	}
	return r.Namespace + "/" + r.Name
}

// Policy is the part of one CNP/CCNP that matters for attribution.
type Policy struct {
	Ref Ref
	// Label is the cnpgen/label annotation ("key=value") cnpgen puts on the
	// policies it generates, or "".
	Label string
	// Broad is true when no spec picks pods by their own labels, only by
	// namespace (or not at all): a baseline applying to every pod, which
	// Pick only falls back to.
	Broad bool
	specs []spec
}

// spec is one entry of a policy's spec/specs.
type spec struct {
	sel      selector
	covers   [2]bool // indexed by Dir: has rules (or default deny) in that direction
	allowAll [2]bool // indexed by Dir: has an allow-all rule in that direction
}

// TargetAnnotation is the annotation cnpgen's generated policies carry, set
// to the -l label they were generated for (generate.TargetAnnotation; not
// imported to keep this package free of the generator).
const TargetAnnotation = "cnpgen/label"

// BootstrapPrefix prefixes the name of cnpgen's temporary DNS visibility
// policy, which is never where a missing rule belongs.
const BootstrapPrefix = "cnpgen-bootstrap-dns-"

// Parse builds a Policy from a raw CNP or CCNP object. ok is false when it
// selects no endpoint (e.g. only nodeSelector host policies).
func Parse(obj map[string]any) (p *Policy, ok bool) {
	meta, _ := obj["metadata"].(map[string]any)
	ns, _ := meta["namespace"].(string)
	name, _ := meta["name"].(string)
	if obj["kind"] == "CiliumClusterwideNetworkPolicy" {
		ns = ""
	}
	p = &Policy{Ref: Ref{Namespace: ns, Name: name}, Broad: true}
	if ann, _ := meta["annotations"].(map[string]any); ann != nil {
		p.Label, _ = ann[TargetAnnotation].(string)
	}

	var raw []map[string]any
	if s, ok := obj["spec"].(map[string]any); ok {
		raw = append(raw, s)
	}
	if ss, ok := obj["specs"].([]any); ok {
		for _, s := range ss {
			if m, ok := s.(map[string]any); ok {
				raw = append(raw, m)
			}
		}
	}
	for _, r := range raw {
		es, ok := r["endpointSelector"].(map[string]any)
		if !ok {
			continue // nodeSelector (host policy) or malformed: selects no pod
		}
		sel, err := parseSelector(es)
		if err != nil {
			continue
		}
		if sel.podSpecific() {
			p.Broad = false
		}
		if ns != "" {
			// A CNP only ever selects endpoints in its own namespace.
			sel = append(sel, requirement{src: "k8s", key: "io.kubernetes.pod.namespace", op: "In", values: []string{ns}})
		}
		s := spec{sel: sel}
		dd, _ := r["enableDefaultDeny"].(map[string]any)
		for _, d := range []Dir{Ingress, Egress} {
			allow, deny := "ingress", "ingressDeny"
			if d == Egress {
				allow, deny = "egress", "egressDeny"
			}
			_, hasAllow := r[allow]
			_, hasDeny := r[deny]
			s.covers[d] = hasAllow || hasDeny || dd[d.String()] == true
			rules, _ := r[allow].([]any)
			for _, rule := range rules {
				if m, ok := rule.(map[string]any); ok && isAllowAll(m, d) {
					s.allowAll[d] = true
				}
			}
		}
		p.specs = append(p.specs, s)
	}
	return p, len(p.specs) > 0
}

// isAllowAll reports whether one allow rule lets any peer through on any
// port: the entity "all" with no toPorts/icmps. An empty rule ({}) is not one,
// Cilium treats it as allowing nothing.
func isAllowAll(rule map[string]any, d Dir) bool {
	ents := "fromEntities"
	ports, icmps := "toPorts", "icmps"
	if d == Egress {
		ents = "toEntities"
	}
	if l, _ := rule[ports].([]any); len(l) > 0 {
		return false
	}
	if l, _ := rule[icmps].([]any); len(l) > 0 {
		return false
	}
	l, _ := rule[ents].([]any)
	for _, e := range l {
		if e == "all" {
			return true
		}
	}
	return false
}

// selects reports whether any spec selects ep, and folds what those specs
// say about direction d into covers/allowAll.
func (p *Policy) selects(ep endpointLabels, d Dir) (selected, covers, allowAll bool) {
	for _, s := range p.specs {
		if !s.sel.matches(ep) {
			continue
		}
		selected = true
		covers = covers || s.covers[d]
		allowAll = allowAll || s.allowAll[d]
	}
	return selected, covers, allowAll
}

// Match is what the index knows about one endpoint in one direction.
type Match struct {
	// Policies selecting the endpoint that have rules (or default deny) in
	// the direction, sorted by Ref. When none do, every policy selecting the
	// endpoint, so a rule still lands next to the pod's own policy.
	Policies []*Policy
	// AllowAll is true when one of them allows everything in the direction:
	// a policy_match_type 4 flow there is allowed, not missing a rule.
	AllowAll bool
}

// Index is an immutable set of policies plus a lookup cache. Not safe for
// concurrent use: the cache is filled on lookups, so callers serialize.
type Index struct {
	policies []*Policy
	cache    map[cacheKey]Match
}

type cacheKey struct {
	identity uint32
	dir      Dir
}

// maxCache bounds the lookup cache. Cilium identities are a bounded set
// already; this only guards against a pathological cluster.
const maxCache = 1 << 16

// New builds an Index over policies.
func New(policies []*Policy) *Index {
	sorted := append([]*Policy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool { return less(sorted[i].Ref, sorted[j].Ref) })
	return &Index{policies: sorted, cache: map[cacheKey]Match{}}
}

// Len returns the number of policies indexed.
func (ix *Index) Len() int { return len(ix.policies) }

func less(a, b Ref) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	return a.Name < b.Name
}

// Match returns the policies applying to ep in direction d.
func (ix *Index) Match(ep hubble.Endpoint, d Dir) Match {
	key := cacheKey{identity: ep.Identity, dir: d}
	if ep.Identity != 0 {
		if m, ok := ix.cache[key]; ok {
			return m
		}
	}
	el := parseEndpoint(ep)
	var m Match
	var selecting []*Policy
	for _, p := range ix.policies {
		sel, covers, allowAll := p.selects(el, d)
		if !sel {
			continue
		}
		selecting = append(selecting, p)
		if covers {
			m.Policies = append(m.Policies, p)
			m.AllowAll = m.AllowAll || allowAll
		}
	}
	if len(m.Policies) == 0 {
		m.Policies = selecting
	}
	if ep.Identity != 0 {
		if len(ix.cache) >= maxCache {
			ix.cache = map[cacheKey]Match{}
		}
		ix.cache[key] = m
	}
	return m
}

// Pick chooses which of m's policies a missing rule for ep goes to, and
// returns the others that would work as well. Candidates are ranked: a
// policy selecting pods by their own labels first, then a Broad one, then
// one excluded by ex, and cnpgen's bootstrap DNS policy last (never listed
// in others). Within the best rank, a cnpgen-generated policy whose
// cnpgen/label matches the pod is preferred; otherwise the first by name.
// primary is nil when no policy applies.
func Pick(m Match, ep hubble.Endpoint, ex Excludes) (primary *Policy, others []*Policy) {
	if len(m.Policies) == 0 {
		return nil, nil
	}
	rank := func(p *Policy) int {
		switch {
		case strings.HasPrefix(p.Ref.Name, BootstrapPrefix):
			return 3
		case ex.Has(p.Ref):
			return 2
		case p.Broad:
			return 1
		}
		return 0
	}
	best, bestRank, bestLabel := -1, 0, false
	for i, p := range m.Policies {
		r := rank(p)
		label := p.Label != "" && labels.HasLabel(ep.Labels, p.Label)
		if best < 0 || r < bestRank || (r == bestRank && label && !bestLabel) {
			best, bestRank, bestLabel = i, r, label
		}
	}
	for i, p := range m.Policies {
		if i != best && !strings.HasPrefix(p.Ref.Name, BootstrapPrefix) {
			others = append(others, p)
		}
	}
	return m.Policies[best], others
}

// Excludes are policies a missing rule should not go to unless nothing else
// selects the pod (verify --exclude-policy). Each entry is a path.Match
// pattern against "namespace/name" ("clusterwide/name" for a CCNP), or
// against the bare name when it has no '/'.
type Excludes []string

// ValidateExclude reports a malformed pattern.
func ValidateExclude(pattern string) error {
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("bad policy pattern %q: %w", pattern, err)
	}
	return nil
}

// Has reports whether r matches one of the patterns.
func (ex Excludes) Has(r Ref) bool {
	for _, pat := range ex {
		target := r.String()
		if !strings.Contains(pat, "/") {
			target = r.Name
		}
		if ok, _ := path.Match(pat, target); ok {
			return true
		}
	}
	return false
}

// Lister lists raw policy objects (kube.Client in production).
type Lister interface {
	ListPolicies(ctx context.Context, namespace string) ([]map[string]any, error)
	ListClusterwidePolicies(ctx context.Context) ([]map[string]any, error)
}

// Source loads policies from the cluster and tells when they changed.
type Source struct {
	k         Lister
	namespace string // "" for all namespaces
	sig       string
	ccnpErr   bool // clusterwide listing failed before; warn only once
}

// NewSource returns a Source listing CNPs in namespace ("" for all) plus
// every CCNP (which can select pods in any namespace).
func NewSource(k Lister, namespace string) *Source {
	return &Source{k: k, namespace: namespace}
}

// Load lists the policies and returns a fresh Index, or nil when nothing
// changed since the previous Load. warn is a non-fatal problem to report
// (clusterwide policies couldn't be listed), "" otherwise.
func (s *Source) Load(ctx context.Context) (ix *Index, warn string, err error) {
	objs, err := s.k.ListPolicies(ctx, s.namespace)
	if err != nil {
		return nil, "", fmt.Errorf("listing CiliumNetworkPolicies: %w", err)
	}
	cw, cerr := s.k.ListClusterwidePolicies(ctx)
	if cerr != nil {
		if !s.ccnpErr {
			warn = fmt.Sprintf("listing CiliumClusterwideNetworkPolicies: %v (ignoring them)", cerr)
		}
		s.ccnpErr = true
	} else {
		s.ccnpErr = false
	}
	objs = append(objs, cw...)

	parts := make([]string, 0, len(objs))
	for _, o := range objs {
		meta, _ := o["metadata"].(map[string]any)
		parts = append(parts, fmt.Sprintf("%v/%v", meta["uid"], meta["resourceVersion"]))
	}
	sort.Strings(parts)
	sig := strings.Join(parts, ";")
	if sig == s.sig {
		return nil, warn, nil
	}
	s.sig = sig

	policies := make([]*Policy, 0, len(objs))
	for _, o := range objs {
		if p, ok := Parse(o); ok {
			policies = append(policies, p)
		}
	}
	return New(policies), warn, nil
}

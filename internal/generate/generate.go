// Package generate turns a connection graph + resolve index + settings into
// per-app CiliumNetworkPolicy documents.
//
// Each policy:
//   - emits enableDefaultDeny:{ingress,egress}:false so it deploys safely
//   - routes external IPs through resolve+patterns into toFQDNs where possible,
//     falling back to toCIDR otherwise
//   - always allows the Kubernetes API server, plus any --allow-extra egress
//   - carries a kube-dns DNS-visibility rule (temporary, pruned later if unused)
package generate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/patterns"
	"github.com/kwistof/cnpgen/internal/settings"
	"github.com/kwistof/cnpgen/internal/ui"
)

// Managed-by label marking a CiliumNetworkPolicy as cnpgen-owned (see deploy).
const (
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "cnpgen"

	BootstrapDNSPolicyName = "cnpgen-bootstrap-dns"
)

// wellKnownIPComment annotates a handful of fixed IPs that never resolve to a
// real domain name, so an unresolved toCIDR fallback at least says what the
// IP is instead of leaving the operator to guess.
func wellKnownIPComment(ip string) string {
	switch ip {
	case "169.254.169.254":
		return "cloud instance metadata service (AWS/Azure/GCP/etc.)"
	default:
		return ""
	}
}

// Policy is a generated CiliumNetworkPolicy plus the metadata the pipeline and
// report need.
type Policy struct {
	Name          string
	Namespace     string // deploy namespace (metadata.namespace)
	ObservedNS    string // namespace the traffic was observed in
	doc           *omap  // the ordered policy document
	spec          *omap
	cidrComments  commentLookup
	dnsRule       *omap // the injected DNS rule, if injected whole (for pruning)
	dnsMergedRule *omap // a real rule the DNS block was merged into (for pruning)
	Suggestions   []patterns.Suggestion
	Unresolved    []Unresolved
	Notes         []string
}

// Unresolved is an external CIDR that couldn't be resolved to an FQDN.
type Unresolved struct {
	CIDR  string
	Port  int32
	Proto string
}

// Object returns the policy as a plain map for the dynamic Kubernetes client.
func (p *Policy) Object() map[string]any {
	return toPlain(p.doc).(map[string]any)
}

// SetDeployNamespace sets the policy object's own metadata.namespace (where it
// is written/deployed), independent of the namespace its traffic was observed
// in. ObservedNS is left unchanged so file naming stays collision-safe.
func (p *Policy) SetDeployNamespace(ns string) {
	p.Namespace = ns
	if p.doc == nil {
		return
	}
	if meta, ok := p.doc.get("metadata"); ok {
		meta.(*omap).set("namespace", ns)
	}
}

// FileName returns the output file name for this policy, keyed by the namespace
// its traffic was observed in (not the deploy namespace) so two apps with the
// same name from different source namespaces never collide.
func (p *Policy) FileName() string {
	ns := p.ObservedNS
	if ns == "" {
		ns = p.Namespace
	}
	return ns + "-" + p.Name + ".yaml"
}

// YAML renders the policy to a YAML document string.
func (p *Policy) YAML() string {
	return renderYAML(p.doc, p.cidrComments)
}

// portProto is a (port, proto) pair used for grouping.
type portProto struct {
	Port  int32
	Proto string
}

// buildPorts builds a Cilium toPorts list ([]any of one omap) from port/proto
// pairs. Dedups, skips port 0. Returns nil if empty.
func buildPorts(pps []portProto) []any {
	type pp struct {
		port  string
		proto string
	}
	var ordered []pp
	seen := map[pp]struct{}{}
	sorted := append([]portProto(nil), pps...)
	sort.Slice(sorted, func(i, j int) bool {
		pi := strconv.Itoa(int(sorted[i].Port))
		pj := strconv.Itoa(int(sorted[j].Port))
		if pi != pj {
			return pi < pj
		}
		return sorted[i].Proto < sorted[j].Proto
	})
	for _, x := range sorted {
		if x.Port == 0 {
			continue
		}
		proto := x.Proto
		if proto == "" {
			proto = "TCP"
		}
		key := pp{port: strconv.Itoa(int(x.Port)), proto: proto}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ordered = append(ordered, key)
	}
	if len(ordered) == 0 {
		return nil
	}
	var ports []any
	for _, x := range ordered {
		ports = append(ports, newOMap().set("port", x.port).set("protocol", x.proto))
	}
	return []any{newOMap().set("ports", ports)}
}

// BootstrapDNSPolicy is a standalone DNS-visibility policy for when no app
// policy exists yet, so Cilium's FQDN cache starts learning IP->domain mappings
// from the first round. The endpointSelector matches `label` if given, else
// every pod in the namespace.
func BootstrapDNSPolicy(namespace, label string) *Policy {
	var selector *omap
	if label != "" && strings.Contains(label, "=") {
		key, val, _ := strings.Cut(label, "=")
		selector = newOMap().set("matchLabels",
			newOMap().set(strings.TrimSpace(key), strings.TrimSpace(val)))
	} else {
		selector = newOMap()
	}
	dnsRule := newOMap().
		set("toEndpoints", []any{newOMap().set("matchLabels", newOMap().
			set("k8s-app", "kube-dns").
			set("io.kubernetes.pod.namespace", "kube-system"))}).
		set("toPorts", []any{newOMap().
			set("ports", []any{newOMap().set("port", "53").set("protocol", "UDP")}).
			set("rules", newOMap().set("dns", []any{newOMap().set("matchPattern", "*")}))})

	spec := newOMap().
		set("enableDefaultDeny", newOMap().set("ingress", false).set("egress", false)).
		set("endpointSelector", selector).
		set("egress", []any{dnsRule})

	doc := newOMap().
		set("apiVersion", "cilium.io/v2").
		set("kind", "CiliumNetworkPolicy").
		set("metadata", newOMap().
			set("name", BootstrapDNSPolicyName).
			set("namespace", namespace).
			set("labels", newOMap().set(ManagedByLabel, ManagedByValue))).
		set("spec", spec)

	return &Policy{Name: BootstrapDNSPolicyName, Namespace: namespace, doc: doc}
}

// routeExternal splits egress_external into FQDN groups (per port) and CIDR
// groups (per port), collecting suggestions and unresolved IPs. seed, if not
// nil, is merged in as an unconditional floor: its FQDNs/CIDRs are included
// even if nothing observed this round confirms them.
func routeExternal(bucket *model.ConnBucket, index *model.ResolveIndex,
	cfg settings.Settings, accept bool, seed *Seed) (
	fqdnByPort map[portProto]patterns.Result,
	cidrByPort map[portProto]map[string]string,
	unresolved []Unresolved,
	suggestions []patterns.Suggestion,
) {
	fqdnsByPort := map[portProto]map[string]struct{}{}
	cidrByPort = map[portProto]map[string]string{}

	for c := range bucket.EgressExternal {
		if c.IP == "" || c.IP == "UNKNOWN" {
			continue
		}
		key := portProto{Port: c.Port, Proto: c.Proto}
		var rf *model.ResolvedFqdn
		if index != nil {
			rf = index.ResolvedFor(c.IP)
		}
		if rf != nil && rf.Resolved() {
			if fqdnsByPort[key] == nil {
				fqdnsByPort[key] = map[string]struct{}{}
			}
			for f := range rf.Fqdns {
				fqdnsByPort[key][f] = struct{}{}
			}
		} else {
			cidr := c.IP
			if !strings.Contains(cidr, "/") {
				cidr += "/32"
			}
			comment := ""
			if rf != nil {
				comment = rf.Comment
			}
			if comment == "" {
				comment = wellKnownIPComment(c.IP)
			}
			if cidrByPort[key] == nil {
				cidrByPort[key] = map[string]string{}
			}
			cidrByPort[key][cidr] = comment
			unresolved = append(unresolved, Unresolved{CIDR: cidr, Port: c.Port, Proto: c.Proto})
		}
	}

	seed.mergeInto(fqdnsByPort, cidrByPort)

	fqdnByPort = map[portProto]patterns.Result{}
	for key, fqdns := range fqdnsByPort {
		res := patterns.Collapse(setToSlice(fqdns), cfg.AllowDomains, cfg.PinDomains, accept)
		fqdnByPort[key] = res
		suggestions = append(suggestions, res.Suggestions...)
	}
	return fqdnByPort, cidrByPort, unresolved, suggestions
}

// suggestMarker and wildcardMarker prefix the block comment cnpgen writes
// above a matchName group it could wildcard (declined) or a matchPattern
// entry it did wildcard (accepted/forced). `cnpgen review` looks for these
// exact prefixes to find and toggle groups; keep them in sync with the
// parser in internal/review.
const (
	suggestMarker  = "cnpgen:suggest"
	wildcardMarker = "cnpgen:wildcard"
)

func fqdnPatternSuffix(pattern string) string {
	return strings.TrimPrefix(pattern, "*.")
}

// fqdnRule builds the toFQDNs entries for one port group's Collapse result.
// Domains covered by a declined Suggestion are grouped into a contiguous run
// of matchName entries with a marker comment on the first one; an
// accepted/forced Suggestion becomes a single matchPattern entry with a
// marker comment listing the domains it covers. Everything else renders as a
// plain, uncommented entry in the usual sorted order.
func fqdnRule(res patterns.Result, pps []portProto) *omap {
	declinedSuffix := map[string]string{} // domain -> suffix, declined suggestions only
	membersOf := map[string][]string{}    // suffix -> sorted members
	for _, s := range res.Suggestions {
		if s.Forced || s.Accepted {
			continue // represented as a matchPattern below instead
		}
		membersOf[s.Suffix] = mergeSorted(membersOf[s.Suffix], s.Members)
		for _, m := range s.Members {
			declinedSuffix[m] = s.Suffix
		}
	}

	var entries []any
	emitted := map[string]bool{}
	for _, name := range res.MatchNames {
		if emitted[name] {
			continue
		}
		suffix, grouped := declinedSuffix[name]
		if !grouped {
			entries = append(entries, newOMap().set("matchName", name))
			emitted[name] = true
			continue
		}
		members := membersOf[suffix]
		entries = append(entries, newOMap().set("matchName", members[0]).withComment(fmt.Sprintf(
			"%s *.%s (%d domains: %s) - re-run with --allow-domain '*.%s', or 'cnpgen review' to accept.",
			suggestMarker, suffix, len(members), strings.Join(members, ", "), suffix)))
		emitted[members[0]] = true
		for _, m := range members[1:] {
			entries = append(entries, newOMap().set("matchName", m))
			emitted[m] = true
		}
	}
	for _, pat := range res.MatchPatterns {
		entry := newOMap().set("matchPattern", pat)
		suffix := fqdnPatternSuffix(pat)
		for _, s := range res.Suggestions {
			if s.Suffix == suffix && (s.Forced || s.Accepted) {
				entry.withComment(fmt.Sprintf(
					"%s *.%s (%d domains observed: %s)",
					wildcardMarker, suffix, len(s.Members), strings.Join(s.Members, ", ")))
				break
			}
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil
	}
	rule := newOMap().set("toFQDNs", entries)
	if ports := buildPorts(pps); ports != nil {
		rule.set("toPorts", ports)
	}
	return rule
}

// BuildPolicy builds a per-app CiliumNetworkPolicy. Returns nil if the app has
// no ingress/egress rules (a reserved identity, or nothing observed). seed,
// if not nil, is merged in as an unconditional floor (see routeExternal).
func BuildPolicy(app, ns string, bucket *model.ConnBucket, index *model.ResolveIndex,
	cfg settings.Settings, accept, tempDNS bool, seed *Seed) *Policy {

	selector := labels.AppToLabelSelector(app)
	if selector == nil {
		return nil
	}

	p := &Policy{
		Name:         labels.AppToPolicyName(app),
		Namespace:    ns,
		ObservedNS:   ns,
		cidrComments: commentLookup{},
	}

	var egressRules []any
	var ingressRules []any

	// ---- ingress from apps ----
	ingressMap := map[model.Endpoint][]portProto{}
	for c := range bucket.IngressApps {
		ingressMap[c.Peer] = append(ingressMap[c.Peer], portProto{c.Port, c.Proto})
	}
	for _, peer := range sortedEndpoints(ingressMap) {
		srcSel := labels.AppToLabelSelector(peer.App)
		if srcSel == nil {
			continue
		}
		ml := newOMap()
		for _, k := range sortedMapKeys(srcSel) {
			ml.set(k, srcSel[k])
		}
		if peer.Namespace != "" && peer.Namespace != ns {
			ml.set("io.kubernetes.pod.namespace", peer.Namespace)
		}
		rule := newOMap().set("fromEndpoints", []any{newOMap().set("matchLabels", ml)})
		if ports := buildPorts(ingressMap[peer]); ports != nil {
			rule.set("toPorts", ports)
		}
		ingressRules = append(ingressRules, rule)
	}

	// ---- egress to apps ----
	egressMap := map[model.Endpoint][]portProto{}
	for c := range bucket.EgressApps {
		egressMap[c.Peer] = append(egressMap[c.Peer], portProto{c.Port, c.Proto})
	}
	for _, peer := range sortedEndpoints(egressMap) {
		var rule *omap
		switch {
		case strings.HasPrefix(peer.App, "reserved:kube-apiserver"):
			rule = newOMap().set("toEntities", []any{"kube-apiserver"})
		case strings.HasPrefix(peer.App, "reserved:host"):
			rule = newOMap().set("toEntities", []any{"host"})
		default:
			dstSel := labels.AppToLabelSelector(peer.App)
			if dstSel == nil {
				continue
			}
			ml := newOMap()
			for _, k := range sortedMapKeys(dstSel) {
				ml.set(k, dstSel[k])
			}
			if peer.Namespace != "" && peer.Namespace != ns {
				ml.set("io.kubernetes.pod.namespace", peer.Namespace)
			}
			rule = newOMap().set("toEndpoints", []any{newOMap().set("matchLabels", ml)})
		}
		if ports := buildPorts(egressMap[peer]); ports != nil {
			rule.set("toPorts", ports)
		}
		egressRules = append(egressRules, rule)
	}

	// ---- egress to external (FQDN / CIDR) ----
	fqdnByPort, cidrByPort, unresolved, suggestions := routeExternal(bucket, index, cfg, accept, seed)
	// Map iteration order is random; sort so the note text and p.Unresolved are
	// deterministic (by port group, then CIDR).
	sort.Slice(unresolved, func(i, j int) bool {
		pi := portProto{unresolved[i].Port, unresolved[i].Proto}
		pj := portProto{unresolved[j].Port, unresolved[j].Proto}
		if pi != pj {
			return lessPortProto(pi, pj)
		}
		return unresolved[i].CIDR < unresolved[j].CIDR
	})
	p.Suggestions = suggestions
	p.Unresolved = unresolved

	// Merge suggestions by suffix so a suffix spanning several port groups is
	// noted once with the full member count.
	bySuffix := map[string]patterns.Suggestion{}
	var suffixOrder []string
	for _, s := range suggestions {
		if existing, ok := bySuffix[s.Suffix]; ok {
			existing.Members = mergeSorted(existing.Members, s.Members)
			bySuffix[s.Suffix] = existing
		} else {
			bySuffix[s.Suffix] = s
			suffixOrder = append(suffixOrder, s.Suffix)
		}
	}
	sort.Strings(suffixOrder)
	for _, suffix := range suffixOrder {
		s := bySuffix[suffix]
		switch {
		case s.Forced:
			p.Notes = append(p.Notes, fmt.Sprintf(
				"combined %d domains into *.%s (--allow-domain).", len(s.Members), s.Suffix))
		case s.Accepted:
			p.Notes = append(p.Notes, fmt.Sprintf(
				"combined %d domains into *.%s (--accept-suggestions).", len(s.Members), s.Suffix))
		default:
			p.Notes = append(p.Notes, fmt.Sprintf(
				"could combine %d domains into *.%s (%s) but didn't.\n    %s",
				len(s.Members), s.Suffix, strings.Join(s.Members, ", "),
				ui.Dim(fmt.Sprintf("Fix: re-run with --allow-domain '*.%s', use --accept-suggestions, or 'cnpgen review'.", s.Suffix))))
		}
	}

	hasFqdns := false
	for _, r := range fqdnByPort {
		if len(r.MatchNames) > 0 || len(r.MatchPatterns) > 0 {
			hasFqdns = true
			break
		}
	}

	// Group FQDN results that share an identical FQDN-set across ports into a
	// single toFQDNs block with a combined toPorts list.
	type fqdnKey struct {
		names    string
		patterns string
	}
	fqdnGroups := map[fqdnKey][]portProto{}
	fqdnGroupData := map[fqdnKey]patterns.Result{}
	for key, res := range fqdnByPort {
		if len(res.MatchNames) == 0 && len(res.MatchPatterns) == 0 {
			continue
		}
		gk := fqdnKey{names: strings.Join(res.MatchNames, ","), patterns: strings.Join(res.MatchPatterns, ",")}
		fqdnGroups[gk] = append(fqdnGroups[gk], key)
		fqdnGroupData[gk] = res
	}
	var gkeys []fqdnKey
	for gk := range fqdnGroups {
		gkeys = append(gkeys, gk)
	}
	sort.Slice(gkeys, func(i, j int) bool {
		if gkeys[i].names != gkeys[j].names {
			return gkeys[i].names < gkeys[j].names
		}
		return gkeys[i].patterns < gkeys[j].patterns
	})
	allExactNames := map[string]struct{}{}
	for _, gk := range gkeys {
		res := fqdnGroupData[gk]
		rule := fqdnRule(res, fqdnGroups[gk])
		if rule != nil {
			egressRules = append(egressRules, rule)
			for _, n := range res.MatchNames {
				allExactNames[n] = struct{}{}
			}
		}
	}
	if len(allExactNames) > 0 {
		names := setToSlice(allExactNames)
		sort.Strings(names)
		p.Notes = append(p.Notes, fmt.Sprintf(
			"resolved and allowed %d domain(s): %s.", len(names), strings.Join(names, ", ")))
	}

	for _, key := range sortedPortKeys(cidrByPort) {
		cidrMap := cidrByPort[key]
		cidrs := setToSlice(mapKeysSet(cidrMap))
		sort.Strings(cidrs)
		var list []any
		for _, c := range cidrs {
			list = append(list, c)
			if cm := cidrMap[c]; cm != "" {
				p.cidrComments[c] = cm
			}
		}
		rule := newOMap().set("toCIDR", list)
		if ports := buildPorts([]portProto{key}); ports != nil {
			rule.set("toPorts", ports)
		}
		egressRules = append(egressRules, rule)
	}

	if len(unresolved) > 0 {
		var parts []string
		for _, u := range unresolved {
			parts = append(parts, fmt.Sprintf("%s (port %d/%s)", u.CIDR, u.Port, u.Proto))
		}
		p.Notes = append(p.Notes, fmt.Sprintf(
			"couldn't resolve %d IP(s), kept as toCIDR: %s.\n    %s",
			len(unresolved), strings.Join(parts, ", "),
			ui.Dim("Fix: re-run with --known-ip '<ip>=<domain>', or wait for more DNS traffic.")))
	}

	// ---- boilerplate egress ----
	if len(egressRules) > 0 || len(ingressRules) > 0 || hasFqdns {
		egressRules = p.appendBoilerplate(egressRules, cfg, hasFqdns, tempDNS)
	}

	if len(egressRules) == 0 && len(ingressRules) == 0 {
		return nil
	}

	spec := newOMap().
		set("enableDefaultDeny", newOMap().set("ingress", false).set("egress", false)).
		set("endpointSelector", newOMap().set("matchLabels", mapToOMap(selector)))
	if len(ingressRules) > 0 {
		spec.set("ingress", ingressRules)
	}
	if len(egressRules) > 0 {
		spec.set("egress", egressRules)
	}
	p.spec = spec

	p.doc = newOMap().
		set("apiVersion", "cilium.io/v2").
		set("kind", "CiliumNetworkPolicy").
		set("metadata", newOMap().
			set("name", p.Name).
			set("namespace", ns).
			set("labels", newOMap().set(ManagedByLabel, ManagedByValue))).
		set("spec", spec)

	return p
}

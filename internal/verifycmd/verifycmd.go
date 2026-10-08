// Package verifycmd watches live traffic against whatever CiliumNetworkPolicy
// is already deployed (cnpgen's own, hand written, or from any other tool)
// and reports what it does not allow. It never generates, deploys, or deletes
// anything on the cluster.
//
// It runs as one never-ending pass: every blocked flow is logged as it
// arrives, and rules files with the egress/ingress entries that would allow
// them are rewritten (at most every few seconds) when a new one shows up.
// With a label (-l), it checks one set of pods and writes one file. With
// --all, it checks every policy in the cluster (or a namespace) through a
// single flow stream per Cilium agent, and writes one file per policy that
// misses rules.
//
// Memory is bounded by the number of distinct missing rules and of policies,
// never by traffic volume: flows are classified and dropped as they arrive.
package verifycmd

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kwistof/cnpgen/internal/collect"
	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/pipeline"
	"github.com/kwistof/cnpgen/internal/policyindex"
	"github.com/kwistof/cnpgen/internal/resolve"
	"github.com/kwistof/cnpgen/internal/ui"
)

// maxRules caps the number of distinct (peer, port) entries kept across all
// files, so pods talking to an unbounded set of raw IPs can't grow memory
// forever. Past the cap, blocked flows are still logged, just no longer
// added to a file.
const maxRules = 10000

// writeEvery rate-limits rewriting rules files: rendering is O(rules), so
// rewriting on every new rule would churn memory when many arrive at once.
const writeEvery = 2 * time.Second

// fqdnRefreshEvery rate-limits re-fetching the live FQDN cache when a blocked
// flow goes to an external IP the current snapshot doesn't know yet.
const fqdnRefreshEvery = time.Minute

// policyRefreshEvery is how often the deployed policies are re-listed, so
// edits (e.g. a rule just added from a missing-rules file) are picked up.
// A blocked flow no policy explains triggers an earlier re-list, at most
// every policyRefreshMin.
const (
	policyRefreshEvery = 30 * time.Second
	policyRefreshMin   = 5 * time.Second
)

// blockedCEL is the Hubble-side version of blocked: policy_match_type 4, or
// a drop with reason 133 (POLICY_DENIED; Hubble's CEL compares enums by
// number). Flows it rejects never leave the agent, which matters most with
// --all, where the stream is otherwise every flow on the node.
const blockedCEL = "_flow.policy_match_type == 4u || _flow.drop_reason_desc == 133"

// Config holds the verify run parameters.
type Config struct {
	// Label and Namespace select the pods to check. With All, Label is ""
	// and Namespace, if set, only restricts which policies are checked.
	Label     string
	Namespace string
	All       bool
	Out       string // rules file, or with All a directory of them
	FqdnDump  string // resolve from this saved dump instead of the live cache
}

// Run watches until ctx is cancelled (Ctrl+C / SIGTERM). It never writes to
// the cluster.
func Run(ctx context.Context, k *kube.Client, cfg Config) error {
	src := policyindex.NewSource(k, cfg.Namespace)
	if cfg.All {
		scope := "every namespace"
		if cfg.Namespace != "" {
			scope = "namespace " + cfg.Namespace
		}
		fmt.Println(ui.Bold("Verifying every policy in " + scope + "."))
		fmt.Println(ui.Dim(fmt.Sprintf("  Read-only. Logs every flow a deployed policy blocks and writes the rules "+
			"to allow them to %s/<namespace>/<policy>.missing.yaml. Ctrl+C to stop.", cfg.Out)))
		if err := os.MkdirAll(cfg.Out, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", cfg.Out, err)
		}
	} else {
		target := pipeline.DescribeTarget(cfg.Label, cfg.Namespace)
		fmt.Println(ui.Bold(fmt.Sprintf("Verifying %s.", target)))
		fmt.Println(ui.Dim(fmt.Sprintf("  Read-only. Logs every flow the deployed policy blocks and writes the rules "+
			"to allow them to %s. Ctrl+C to stop.", cfg.Out)))
		if n, err := k.CountPodsMatching(ctx, cfg.Label, cfg.Namespace); err != nil {
			ui.Warn("checking for matching pods: %v", err)
		} else if n == 0 {
			fmt.Println(ui.Yellow(fmt.Sprintf("  Warning: no pods matching %s right now. Watching anyway.", target)))
		} else {
			fmt.Println(ui.Dim(fmt.Sprintf("  %d pod(s) matching %s.", n, target)))
		}
	}

	ix, warn, err := src.Load(ctx)
	switch {
	case err != nil && cfg.All:
		return err // nothing to attribute flows to
	case err != nil:
		// Only used to tell allow-all rules apart; verify still works without.
		ui.Warn("%v (allow-all rules in the policy may be reported as missing rules)", err)
	case cfg.All:
		fmt.Println(ui.Dim(fmt.Sprintf("  %d policy(ies) selecting pods.", ix.Len())))
	}
	if warn != "" {
		ui.Warn("%s", warn)
	}

	w := newWatcher(cfg, newResolver(ctx, k, cfg.FqdnDump), ix)
	w.ips = newIPInfo(ctx, k)
	if !cfg.All {
		// Write the (empty) file up front, so it exists even if nothing is
		// ever blocked and a bad path fails fast instead of on the first
		// blocked flow.
		if err := w.single.write(); err != nil {
			return err
		}
	}

	follower, err := collect.StartFollowWith(ctx, k, collect.FollowOptions{
		Label: cfg.Label,
		CEL:   blockedCEL,
		Keep:  mayBeBlocked,
	}, w.onFlow)
	if err != nil {
		return fmt.Errorf("starting flow watch: %w", err)
	}
	fmt.Println(ui.Dim("  Watching..."))
	tick := time.NewTicker(writeEvery)
	defer tick.Stop()
	policyTick := time.NewTicker(policyRefreshEvery)
	defer policyTick.Stop()
	lastLoad := time.Now()
	reload := func() {
		lastLoad = time.Now()
		ix, warn, err := src.Load(ctx)
		if err != nil {
			if ctx.Err() == nil {
				ui.Warn("re-listing policies: %v", err)
			}
			return
		}
		if warn != "" {
			ui.Warn("%s", warn)
		}
		if ix != nil {
			w.setIndex(ix)
		}
	}
	for ctx.Err() == nil {
		select {
		case <-tick.C:
			w.flush()
		case <-policyTick.C:
			reload()
		case <-w.reload:
			if time.Since(lastLoad) >= policyRefreshMin {
				reload()
			}
		case <-ctx.Done():
		}
	}
	follower.Wait()

	w.flush()
	w.summary()
	return nil
}

// blocked reports whether the deployed policy doesn't allow this flow: either
// Cilium actually dropped it for lack of an allow rule (enforcing policy), or
// it would under enforcement (policy_match_type 4 on a non-enforcing policy).
// Drops from explicit deny rules (POLICY_DENY) are intended and not reported.
// policy_match_type 4 also covers allow-all rules; classify rules those out.
func blocked(f *hubble.Flow) bool {
	if f.PolicyMatchType == 4 {
		return true
	}
	return f.Verdict == "DROPPED" && f.DropReasonDesc == "POLICY_DENIED"
}

// mayBeBlocked is a cheap pre-check on a raw Hubble JSON line, before it's
// parsed: only lines that could satisfy blocked pass. Hubble emits compact
// JSON and policy_match_type is a single digit.
func mayBeBlocked(line []byte) bool {
	return bytes.Contains(line, []byte(`"policy_match_type":4`)) ||
		bytes.Contains(line, []byte(`"POLICY_DENIED"`))
}

// peerKey identifies one rule in an output file: a direction plus a peer.
type peerKey struct {
	dir   string // "egress" | "ingress"
	kind  string // "fqdn" | "endpoint" | "entity" | "cidr"
	value string // FQDN, canonical app label, entity name, or CIDR
	ns    string // peer namespace, endpoint kind only
}

// portKey is one port of a rule.
type portKey struct {
	port  int32
	proto string
}

// fileKey identifies one output file in --all mode.
type fileKey struct {
	ref          policyindex.Ref
	unattributed bool // ref.Namespace/ref.Name are then the pods' namespace/app
}

// ruleSet is the deduplicated rules of one output file.
type ruleSet struct {
	path   string
	name   string              // short name for log lines ("ns/policy")
	title  string              // what the rules are missing from, for the header
	note   string              // extra header line, or ""
	others map[string]struct{} // other policies the rules could go to instead
	rules  map[peerKey]map[portKey]struct{}
	n      int // (peer, port) entries in rules
	dirty  bool
}

func newRuleSet(path, name, title, note string) *ruleSet {
	return &ruleSet{path: path, name: name, title: title, note: note,
		others: map[string]struct{}{}, rules: map[peerKey]map[portKey]struct{}{}}
}

// watcher turns blocked flows into log lines and deduplicated rule sets.
type watcher struct {
	cfg     Config
	res     *resolver
	ips     *ipInfo    // nil: don't look up IPs Cilium has no identity for
	mu      sync.Mutex // onFlow is called concurrently, one goroutine per Cilium pod
	ix      *policyindex.Index
	single  *ruleSet // label mode's only file
	sets    map[fileKey]*ruleSet
	count   int // total (peer, port) entries across all sets
	blocked int
	capHit  bool
	reload  chan struct{} // asks Run to re-list policies (non-blocking send)
}

func newWatcher(cfg Config, res *resolver, ix *policyindex.Index) *watcher {
	w := &watcher{cfg: cfg, res: res, ix: ix, sets: map[fileKey]*ruleSet{}, reload: make(chan struct{}, 1)}
	if !cfg.All {
		w.single = newRuleSet(cfg.Out, "",
			"the CiliumNetworkPolicy for "+pipeline.DescribeTarget(cfg.Label, cfg.Namespace), "")
	}
	return w
}

func (w *watcher) setIndex(ix *policyindex.Index) {
	w.mu.Lock()
	w.ix = ix
	w.mu.Unlock()
}

// onFlow is the collect follow callback. Nothing from the flow is kept
// beyond the (peer, port) key it maps to.
func (w *watcher) onFlow(f *hubble.Flow) {
	if f == nil || f.IsReply || f.Type == "SOCK" || !blocked(f) {
		return
	}
	w.mu.Lock()
	rs, pk, port, ok := w.classify(f)
	if !ok {
		w.mu.Unlock()
		return // not a policy we check (e.g. the peer's own egress), allowed by an allow-all rule, or no L4 info
	}
	w.blocked++
	isNew := w.add(rs, pk, port)
	prefix := ""
	if w.cfg.All {
		prefix = "[" + rs.name + "] "
	}
	w.mu.Unlock()

	// Outside the lock: it may call the API server, and must not hold up
	// the other agents' streams meanwhile.
	note := ""
	if pk.kind == "cidr" && w.ips != nil {
		if p, err := netip.ParsePrefix(pk.value); err == nil {
			note = w.ips.describe(p.Addr().String())
		}
	}
	fmt.Println(logLine(f, pk, port, isNew, prefix, note))
}

// flush rewrites the files whose rules changed since their last write.
func (w *watcher) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, rs := range w.allSets() {
		if !rs.dirty {
			continue
		}
		if err := rs.write(); err != nil {
			ui.Warn("%v", err)
			continue
		}
		rs.dirty = false
	}
}

// allSets returns every rule set, sorted by path.
func (w *watcher) allSets() []*ruleSet {
	if w.single != nil {
		return []*ruleSet{w.single}
	}
	out := make([]*ruleSet, 0, len(w.sets))
	for _, rs := range w.sets {
		out = append(out, rs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func (w *watcher) summary() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.cfg.All {
		fmt.Println(ui.Dim(fmt.Sprintf("\nStopped. %d blocked flow(s), %d missing rule(s) in %s.",
			w.blocked, w.count, w.cfg.Out)))
		return
	}
	sets := w.allSets()
	fmt.Println(ui.Dim(fmt.Sprintf("\nStopped. %d blocked flow(s), %d missing rule(s) in %d file(s):",
		w.blocked, w.count, len(sets))))
	for _, rs := range sets {
		fmt.Printf("  %4d  %s\n", rs.n, rs.path)
	}
}

// add records a (peer, port) entry and reports whether it was new.
func (w *watcher) add(rs *ruleSet, pk peerKey, port portKey) bool {
	ports := rs.rules[pk]
	if _, seen := ports[port]; seen {
		return false
	}
	if w.count >= maxRules {
		if !w.capHit {
			w.capHit = true
			ui.Warn("%d distinct missing rules reached; still logging, no longer adding to %s", maxRules, w.cfg.Out)
		}
		return false
	}
	if ports == nil {
		ports = map[portKey]struct{}{}
		rs.rules[pk] = ports
	}
	ports[port] = struct{}{}
	rs.n++
	rs.dirty = true
	w.count++
	return true
}

// classify maps a blocked flow to the rule set it belongs to and the rule
// it's missing. The flow must be enforced at a selected pod: its egress when
// that pod is the source, its ingress when it's the destination.
func (w *watcher) classify(f *hubble.Flow) (*ruleSet, peerKey, portKey, bool) {
	port, proto := f.Port()
	if proto == "" {
		return nil, peerKey{}, portKey{}, false
	}

	var (
		dir      policyindex.Dir
		ep, peer hubble.Endpoint
		peerIP   string
		names    []string
	)
	if w.cfg.All {
		switch f.TrafficDirection {
		case "EGRESS":
			dir, ep, peer, peerIP, names = policyindex.Egress, f.Source, f.Destination, f.DstIP(), f.DestinationNames
		case "INGRESS":
			dir, ep, peer, peerIP = policyindex.Ingress, f.Destination, f.Source, f.SrcIP()
		default:
			return nil, peerKey{}, portKey{}, false
		}
		if isReserved(ep) {
			return nil, peerKey{}, portKey{}, false // host/world policies aren't pod policies
		}
		if w.cfg.Namespace != "" && namespaceOf(ep) != w.cfg.Namespace {
			return nil, peerKey{}, portKey{}, false
		}
	} else {
		srcOurs := collect.IsOurs(f.Source, w.cfg.Label, w.cfg.Namespace)
		dstOurs := collect.IsOurs(f.Destination, w.cfg.Label, w.cfg.Namespace)
		egress, ingress := false, false
		switch f.TrafficDirection {
		case "EGRESS":
			egress = srcOurs
		case "INGRESS":
			ingress = dstOurs
		default:
			egress = srcOurs
			ingress = !srcOurs && dstOurs
		}
		switch {
		case egress:
			dir, ep, peer, peerIP, names = policyindex.Egress, f.Source, f.Destination, f.DstIP(), f.DestinationNames
		case ingress:
			dir, ep, peer, peerIP = policyindex.Ingress, f.Destination, f.Source, f.SrcIP()
		default:
			return nil, peerKey{}, portKey{}, false
		}
	}

	var m policyindex.Match
	if w.ix != nil {
		m = w.ix.Match(ep, dir)
		if f.PolicyMatchType == 4 && m.AllowAll {
			return nil, peerKey{}, portKey{}, false // matched an allow-all rule, not missing one
		}
	}

	// The port names the peer only when it is the destination.
	var peerPort int32
	if dir == policyindex.Egress {
		peerPort = port
	}
	pk := w.peer(peer, peerIP, peerPort, names)
	if pk.value == "" {
		return nil, peerKey{}, portKey{}, false
	}
	pk.dir = dir.String()

	rs := w.single
	if w.cfg.All {
		rs = w.setFor(m, ep)
	}
	return rs, pk, portKey{port: port, proto: proto}, true
}

// setFor returns (creating if needed) the rule set a blocked flow at ep goes
// to: the policy policyindex.Pick chooses, or, when no visible policy selects
// ep, a per-app "unattributed" file (and a policy re-list is requested, in
// case one was created since the last).
func (w *watcher) setFor(m policyindex.Match, ep hubble.Endpoint) *ruleSet {
	primary, others := policyindex.Pick(m, ep)
	if primary == nil {
		ns := namespaceOf(ep)
		name := podName(ep)
		key := fileKey{ref: policyindex.Ref{Namespace: ns, Name: name}, unattributed: true}
		rs := w.sets[key]
		if rs == nil {
			rs = newRuleSet(filepath.Join(w.cfg.Out, "_unattributed", ns, name+".missing.yaml"),
				"unattributed "+ns+"/"+name, "the policy for '"+name+"' pods in "+ns,
				"No CiliumNetworkPolicy cnpgen can see selects these pods (a Kubernetes NetworkPolicy?).")
			w.sets[key] = rs
		}
		select {
		case w.reload <- struct{}{}:
		default:
		}
		return rs
	}
	key := fileKey{ref: primary.Ref}
	rs := w.sets[key]
	if rs == nil {
		dir := primary.Ref.Namespace
		kind := "CiliumNetworkPolicy"
		if primary.Ref.Clusterwide() {
			dir = "_clusterwide"
			kind = "CiliumClusterwideNetworkPolicy"
		}
		rs = newRuleSet(filepath.Join(w.cfg.Out, dir, primary.Ref.Name+".missing.yaml"),
			primary.Ref.String(), kind+" "+primary.Ref.String(), "")
		w.sets[key] = rs
	}
	for _, o := range others {
		if _, seen := rs.others[o.Ref.String()]; !seen {
			rs.others[o.Ref.String()] = struct{}{}
			rs.dirty = true
		}
	}
	return rs
}

func namespaceOf(ep hubble.Endpoint) string {
	if ep.Namespace != "" {
		return ep.Namespace
	}
	return labels.GetNamespace(ep.Labels)
}

func isReserved(ep hubble.Endpoint) bool {
	for _, l := range ep.Labels {
		if strings.HasPrefix(l, "reserved:") {
			return true
		}
	}
	return false
}

// podName names pods no policy selects: their app label, else the pod name.
func podName(ep hubble.Endpoint) string {
	if app := labels.GetApp(ep.Labels); app != "" {
		return labels.AppToPolicyName(app)
	}
	if ep.PodName != "" {
		return ep.PodName
	}
	return "unknown"
}

// peer picks the best identity for the other side of a flow: a pod label
// in-cluster (one of its own labels, or its namespace, when it has no app
// label), a Cilium entity for reserved identities, a resolved FQDN for
// external IPs, otherwise the raw IP as a /32. port is the flow's destination
// port when ep is the destination, else 0 (see labels.GetPeerApp).
func (w *watcher) peer(ep hubble.Endpoint, ip string, port int32, names []string) peerKey {
	app := labels.GetPeerApp(ep.Labels, port)
	if app == "" && !isReserved(ep) {
		app = labels.FallbackSelector(ep.Labels, namespaceOf(ep))
	}
	switch {
	case app != "" && !strings.HasPrefix(app, "reserved:"):
		return peerKey{kind: "endpoint", value: app, ns: namespaceOf(ep)}
	}
	if entity, ok := labels.Entity(app); ok {
		return peerKey{kind: "entity", value: entity}
	}
	if ip == "" {
		return peerKey{}
	}
	for _, n := range names {
		if n = strings.TrimSuffix(n, "."); n != "" {
			return peerKey{kind: "fqdn", value: n}
		}
	}
	if fqdn := w.res.lookup(ip); fqdn != "" {
		return peerKey{kind: "fqdn", value: fqdn}
	}
	if strings.Contains(ip, ":") {
		return peerKey{kind: "cidr", value: ip + "/128"}
	}
	return peerKey{kind: "cidr", value: ip + "/32"}
}

// logLine renders one blocked flow. note, if set, says who holds a peer IP
// Cilium has no identity for.
func logLine(f *hubble.Flow, pk peerKey, port portKey, isNew bool, prefix, note string) string {
	ts := time.Now()
	if t, err := time.Parse(time.RFC3339Nano, f.Time); err == nil {
		ts = t.Local()
	}
	src := describe(f.Source, f.SrcIP())
	dst := describe(f.Destination, f.DstIP())
	switch {
	case pk.dir == "egress" && pk.kind == "fqdn":
		dst = pk.value + " (" + f.DstIP() + ")"
	case pk.dir == "ingress" && pk.kind == "fqdn":
		src = pk.value + " (" + f.SrcIP() + ")"
	case pk.dir == "egress" && note != "":
		dst += " (" + note + ")"
	case pk.dir == "ingress" && note != "":
		src += " (" + note + ")"
	}
	line := fmt.Sprintf("%s  BLOCKED %-7s  %s%s -> %s  %d/%s",
		ts.Format("15:04:05"), pk.dir, prefix, src, dst, port.port, port.proto)
	if isNew {
		return ui.Yellow(line + "  [new rule]")
	}
	return line
}

// describe renders an endpoint as "app.namespace", "pod-name.namespace" for
// a pod with no app label, or its IP when it has no pod identity.
func describe(ep hubble.Endpoint, ip string) string {
	app := labels.GetApp(ep.Labels)
	if app == "" && !isReserved(ep) {
		if ns := namespaceOf(ep); ns != "" {
			name := ep.PodName
			if name == "" {
				name = "?"
			}
			return name + "." + ns
		}
	}
	if app == "" || app == "reserved:world" {
		if ip == "" {
			return "?"
		}
		return ip
	}
	name := labels.AppToPolicyName(app)
	if ns := namespaceOf(ep); ns != "" {
		name += "." + ns
	}
	return name
}

// render writes the rule set as CiliumNetworkPolicy spec fragments, ready to
// paste under the existing policy's egress/ingress lists. Sorted, so the file
// only changes when the set does. Emitted by hand rather than through a YAML
// library: the shape is fixed, and a library's reflection-based emitter
// allocates tens of MB per write once the set gets large.
func (rs *ruleSet) render() []byte {
	keys := make([]peerKey, 0, len(rs.rules))
	for pk := range rs.rules {
		keys = append(keys, pk)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.dir != b.dir {
			return a.dir == "egress"
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.value != b.value {
			return a.value < b.value
		}
		return a.ns < b.ns
	})

	var b bytes.Buffer
	fmt.Fprintf(&b, "# Rules missing from %s.\n"+
		"# Add each list to the same list in the policy's spec. Written by cnpgen verify.\n", rs.title)
	if rs.note != "" {
		fmt.Fprintf(&b, "# %s\n", rs.note)
	}
	if len(rs.others) > 0 {
		others := make([]string, 0, len(rs.others))
		for o := range rs.others {
			others = append(others, o)
		}
		sort.Strings(others)
		fmt.Fprintf(&b, "# These pods are also selected by %s: the rules can go there instead.\n",
			strings.Join(others, ", "))
	}
	if len(keys) == 0 {
		b.WriteString("# Nothing blocked so far.\n")
		return b.Bytes()
	}
	dir := ""
	for _, pk := range keys {
		if pk.dir != dir {
			dir = pk.dir
			b.WriteString(dir + ":\n")
		}
		writeRule(&b, pk, rs.rules[pk])
	}
	return b.Bytes()
}

// writeRule renders one peer and its ports. Egress to kube-dns on port 53
// gets the DNS rule Cilium needs to learn IPs for toFQDNs. Scalars are
// double-quoted (valid YAML) so values like "true" or "8080" stay strings.
func writeRule(b *bytes.Buffer, pk peerKey, ports map[portKey]struct{}) {
	to := pk.dir == "egress"
	pick := func(egress, ingress string) string {
		if to {
			return egress
		}
		return ingress
	}
	switch pk.kind {
	case "fqdn":
		fmt.Fprintf(b, "- toFQDNs:\n  - matchName: %s\n", strconv.Quote(pk.value))
	case "endpoint":
		sel := labels.AppToLabelSelector(pk.value)
		if pk.ns != "" {
			sel["io.kubernetes.pod.namespace"] = pk.ns
		}
		lk := make([]string, 0, len(sel))
		for k := range sel {
			lk = append(lk, k)
		}
		sort.Strings(lk)
		fmt.Fprintf(b, "- %s:\n  - matchLabels:\n", pick("toEndpoints", "fromEndpoints"))
		for _, k := range lk {
			fmt.Fprintf(b, "      %s: %s\n", k, strconv.Quote(sel[k]))
		}
	case "entity":
		fmt.Fprintf(b, "- %s:\n  - %s\n", pick("toEntities", "fromEntities"), strconv.Quote(pk.value))
	case "cidr":
		fmt.Fprintf(b, "- %s:\n  - %s\n", pick("toCIDR", "fromCIDR"), strconv.Quote(pk.value))
	}

	sorted := make([]portKey, 0, len(ports))
	for p := range ports {
		sorted = append(sorted, p)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].port != sorted[j].port {
			return sorted[i].port < sorted[j].port
		}
		return sorted[i].proto < sorted[j].proto
	})
	isDNSPeer := to && pk.kind == "endpoint" && pk.value == "k8s:k8s-app=kube-dns"
	var plain, dns []portKey
	for _, p := range sorted {
		if isDNSPeer && p.port == 53 {
			dns = append(dns, p)
		} else {
			plain = append(plain, p)
		}
	}

	b.WriteString("  toPorts:\n")
	writePorts := func(ps []portKey) {
		b.WriteString("  - ports:\n")
		for _, p := range ps {
			fmt.Fprintf(b, "    - port: \"%d\"\n      protocol: %s\n", p.port, p.proto)
		}
	}
	if len(dns) > 0 {
		writePorts(dns)
		b.WriteString("    rules:\n      dns:\n      - matchPattern: \"*\"\n")
	}
	if len(plain) > 0 {
		writePorts(plain)
	}
}

// write atomically replaces the set's file with its current rules, creating
// the parent directory if needed. The caller holds the watcher's mu, or owns
// the set exclusively.
func (rs *ruleSet) write() error {
	data := rs.render()
	dir := filepath.Dir(rs.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("writing %s: %w", rs.path, err)
	}
	tmp, err := os.CreateTemp(dir, ".cnpgen-verify-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", rs.path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", rs.path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", rs.path, err)
	}
	if err := os.Rename(tmp.Name(), rs.path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", rs.path, err)
	}
	return nil
}

// resolver maps external IPs to FQDNs from Cilium's FQDN cache. In live mode
// it re-fetches the cache on a miss (rate-limited), since IPs looked up after
// startup aren't in the first snapshot. Each refresh replaces the index, so
// its size tracks the cluster's cache, not the run's length.
type resolver struct {
	index   *model.ResolveIndex
	refresh func() (*model.ResolveIndex, error) // nil for a saved dump
	last    time.Time
}

func newResolver(ctx context.Context, k *kube.Client, dump string) *resolver {
	if dump != "" {
		m, err := resolve.FqdnCacheFromDump(dump)
		if err != nil {
			ui.Warn("reading --fqdn-cache %s: %v", dump, err)
			return &resolver{}
		}
		return &resolver{index: resolve.BuildIndex([]resolve.Source{{Name: "fqdn-cache", Map: m}}, nil)}
	}
	r := &resolver{refresh: func() (*model.ResolveIndex, error) {
		m, err := resolve.FqdnCacheLive(ctx, k)
		if err != nil {
			return nil, err
		}
		return resolve.BuildIndex([]resolve.Source{{Name: "fqdn-cache", Map: m}}, nil), nil
	}}
	r.reload()
	return r
}

func (r *resolver) reload() {
	r.last = time.Now()
	idx, err := r.refresh()
	if err != nil {
		ui.Warn("fetching live FQDN cache: %v", err)
		return
	}
	r.index = idx
}

// lookup returns one FQDN for ip, or "".
func (r *resolver) lookup(ip string) string {
	if fqdn := r.find(ip); fqdn != "" {
		return fqdn
	}
	if r.refresh != nil && time.Since(r.last) >= fqdnRefreshEvery {
		r.reload()
		return r.find(ip)
	}
	return ""
}

func (r *resolver) find(ip string) string {
	if r.index == nil {
		return ""
	}
	rf := r.index.ResolvedFor(ip)
	if rf == nil || !rf.Resolved() {
		return ""
	}
	// Deterministic pick when an IP maps to several names.
	names := make([]string, 0, len(rf.Fqdns))
	for n := range rf.Fqdns {
		names = append(names, n)
	}
	sort.Strings(names)
	return names[0]
}

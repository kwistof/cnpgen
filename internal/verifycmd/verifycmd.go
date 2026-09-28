// Package verifycmd watches live traffic against whatever CiliumNetworkPolicy
// is already deployed for a target (cnpgen's own, hand written, or from any
// other tool) and reports what it does not allow. It never generates, deploys,
// or deletes anything on the cluster.
//
// It runs as one never-ending pass: every blocked flow is logged as it
// arrives, and a rules file with the egress/ingress entries that would allow
// them is rewritten (at most every few seconds) when a new one shows up.
// Memory is bounded by the number of distinct missing rules, never by traffic
// volume: flows are classified and dropped as they arrive.
package verifycmd

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/kwistof/cnpgen/internal/resolve"
	"github.com/kwistof/cnpgen/internal/ui"
)

// maxRules caps the number of distinct (peer, port) entries kept, so a pod
// talking to an unbounded set of raw IPs can't grow memory forever. Past the
// cap, blocked flows are still logged, just no longer added to the file.
const maxRules = 10000

// writeEvery rate-limits rewriting the rules file: rendering is O(rules), so
// rewriting on every new rule would churn memory when many arrive at once.
const writeEvery = 2 * time.Second

// fqdnRefreshEvery rate-limits re-fetching the live FQDN cache when a blocked
// flow goes to an external IP the current snapshot doesn't know yet.
const fqdnRefreshEvery = time.Minute

// Config holds the verify run parameters.
type Config struct {
	Label     string
	Namespace string
	Out       string // rules file, rewritten as new missing rules appear
	FqdnDump  string // resolve from this saved dump instead of the live cache
}

// Run watches until ctx is cancelled (Ctrl+C / SIGTERM). It never writes to
// the cluster.
func Run(ctx context.Context, k *kube.Client, cfg Config) error {
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

	w := newWatcher(cfg, newResolver(ctx, k, cfg.FqdnDump))
	// Write the (empty) file up front, so it exists even if nothing is ever
	// blocked and a bad path fails fast instead of on the first blocked flow.
	if err := w.write(); err != nil {
		return err
	}

	follower, err := collect.StartFollow(ctx, k, cfg.Label, w.onFlow)
	if err != nil {
		return fmt.Errorf("starting flow watch: %w", err)
	}
	fmt.Println(ui.Dim("  Watching..."))
	tick := time.NewTicker(writeEvery)
	defer tick.Stop()
	for ctx.Err() == nil {
		select {
		case <-tick.C:
			w.flush()
		case <-ctx.Done():
		}
	}
	if err := follower.Wait(); err != nil {
		ui.Warn("flow watch: %v", err)
	}

	w.flush()
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Println(ui.Dim(fmt.Sprintf("\nStopped. %d blocked flow(s), %d missing rule(s) in %s.",
		w.blocked, w.count, cfg.Out)))
	return nil
}

// blocked reports whether the deployed policy doesn't allow this flow: either
// Cilium actually dropped it for lack of an allow rule (enforcing policy), or
// it would under enforcement (policy_match_type 4 on a non-enforcing policy).
// Drops from explicit deny rules (POLICY_DENY) are intended and not reported.
func blocked(f *hubble.Flow) bool {
	if f.PolicyMatchType == 4 {
		return true
	}
	return f.Verdict == "DROPPED" && f.DropReasonDesc == "POLICY_DENIED"
}

// peerKey identifies one rule in the output file: a direction plus a peer.
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

// watcher turns blocked flows into log lines and a deduplicated rule set.
type watcher struct {
	cfg     Config
	res     *resolver
	mu      sync.Mutex // onFlow is called concurrently, one goroutine per Cilium pod
	rules   map[peerKey]map[portKey]struct{}
	count   int // total (peer, port) entries across rules
	blocked int
	capHit  bool
	dirty   bool // rules changed since the last write
}

func newWatcher(cfg Config, res *resolver) *watcher {
	return &watcher{cfg: cfg, res: res, rules: map[peerKey]map[portKey]struct{}{}}
}

// onFlow is the collect.StartFollow callback. Nothing from the flow is kept
// beyond the (peer, port) key it maps to.
func (w *watcher) onFlow(f *hubble.Flow) {
	if f == nil || f.IsReply || f.Type == "SOCK" || !blocked(f) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	pk, port, ok := w.classify(f)
	if !ok {
		return // not our pods' policy (e.g. the peer's own egress), or no L4 info
	}
	w.blocked++
	isNew := w.add(pk, port)
	fmt.Println(logLine(f, pk, port, isNew))
	if isNew {
		w.dirty = true
	}
}

// flush rewrites the rules file if it changed since the last write.
func (w *watcher) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.dirty {
		return
	}
	if err := w.write(); err != nil {
		ui.Warn("%v", err)
		return
	}
	w.dirty = false
}

// add records a (peer, port) entry and reports whether it was new.
func (w *watcher) add(pk peerKey, port portKey) bool {
	ports := w.rules[pk]
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
		w.rules[pk] = ports
	}
	ports[port] = struct{}{}
	w.count++
	return true
}

// classify maps a blocked flow to the rule our target's policy is missing.
// The flow must be enforced at our pod: its egress when our pod is the
// source, its ingress when our pod is the destination.
func (w *watcher) classify(f *hubble.Flow) (peerKey, portKey, bool) {
	port, proto := f.Port()
	if proto == "" {
		return peerKey{}, portKey{}, false
	}
	srcOurs := collect.IsOurs(f.Source, w.cfg.Label, w.cfg.Namespace)
	dstOurs := collect.IsOurs(f.Destination, w.cfg.Label, w.cfg.Namespace)

	var dir string
	switch f.TrafficDirection {
	case "EGRESS":
		if srcOurs {
			dir = "egress"
		}
	case "INGRESS":
		if dstOurs {
			dir = "ingress"
		}
	default:
		if srcOurs {
			dir = "egress"
		} else if dstOurs {
			dir = "ingress"
		}
	}

	var pk peerKey
	switch dir {
	case "egress":
		pk = w.peer(f.Destination, f.DstIP(), f.DestinationNames)
	case "ingress":
		pk = w.peer(f.Source, f.SrcIP(), nil)
	default:
		return peerKey{}, portKey{}, false
	}
	if pk.value == "" {
		return peerKey{}, portKey{}, false
	}
	pk.dir = dir
	return pk, portKey{port: port, proto: proto}, true
}

// peer picks the best identity for the other side of a flow: a pod label
// in-cluster, a Cilium entity for reserved identities, a resolved FQDN for
// external IPs, otherwise the raw IP as a /32.
func (w *watcher) peer(ep hubble.Endpoint, ip string, names []string) peerKey {
	app := labels.GetApp(ep.Labels)
	switch {
	case app != "" && !strings.HasPrefix(app, "reserved:"):
		ns := ep.Namespace
		if ns == "" {
			ns = labels.GetNamespace(ep.Labels)
		}
		return peerKey{kind: "endpoint", value: app, ns: ns}
	case app != "" && app != "reserved:world":
		return peerKey{kind: "entity", value: strings.TrimPrefix(app, "reserved:")}
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

// logLine renders one blocked flow.
func logLine(f *hubble.Flow, pk peerKey, port portKey, isNew bool) string {
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
	}
	line := fmt.Sprintf("%s  BLOCKED %-7s  %s -> %s  %d/%s",
		ts.Format("15:04:05"), pk.dir, src, dst, port.port, port.proto)
	if isNew {
		return ui.Yellow(line + "  [new rule]")
	}
	return line
}

// describe renders an endpoint as "app.namespace", or its IP when it has no
// pod identity.
func describe(ep hubble.Endpoint, ip string) string {
	app := labels.GetApp(ep.Labels)
	if app == "" || app == "reserved:world" {
		if ip == "" {
			return "?"
		}
		return ip
	}
	name := labels.AppToPolicyName(app)
	ns := ep.Namespace
	if ns == "" {
		ns = labels.GetNamespace(ep.Labels)
	}
	if ns != "" {
		name += "." + ns
	}
	return name
}

// render writes the rule set as CiliumNetworkPolicy spec fragments, ready to
// paste under the existing policy's egress/ingress lists. Sorted, so the file
// only changes when the set does. Emitted by hand rather than through a YAML
// library: the shape is fixed, and a library's reflection-based emitter
// allocates tens of MB per write once the set gets large.
func (w *watcher) render() []byte {
	keys := make([]peerKey, 0, len(w.rules))
	for pk := range w.rules {
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
	fmt.Fprintf(&b, "# Rules missing from the CiliumNetworkPolicy for %s.\n"+
		"# Add each list to the same list in the policy's spec. Written by cnpgen verify.\n",
		pipeline.DescribeTarget(w.cfg.Label, w.cfg.Namespace))
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
		writeRule(&b, pk, w.rules[pk])
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

// write atomically replaces the output file with the current rule set. The
// caller holds w.mu, or owns w exclusively.
func (w *watcher) write() error {
	data := w.render()
	dir := filepath.Dir(w.cfg.Out)
	tmp, err := os.CreateTemp(dir, ".cnpgen-verify-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", w.cfg.Out, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", w.cfg.Out, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", w.cfg.Out, err)
	}
	if err := os.Rename(tmp.Name(), w.cfg.Out); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("writing %s: %w", w.cfg.Out, err)
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

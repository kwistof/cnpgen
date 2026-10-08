// Package collect turns raw Hubble flows into a connection graph, and gathers
// those flows from the cluster by exec'ing `hubble observe` inside every Cilium
// agent pod (batch `--last N` or streaming `--follow`).
//
// "Our" pods are the ones matching both --label and --namespace: the same
// namespace the generated policy is written/deployed into, since a
// CiliumNetworkPolicy's endpointSelector only ever matches pods in its own
// namespace.
package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/ui"
)

func epNamespace(ep hubble.Endpoint) string {
	// Hubble usually sets a top-level namespace, but it's sometimes absent even
	// though the labels carry it, so fall back so pods aren't split into a
	// namespace="" bucket.
	if ep.Namespace != "" {
		return ep.Namespace
	}
	return labels.GetNamespace(ep.Labels)
}

// IsOurs reports whether an endpoint is one of the target pods: matching both
// `label` and `namespace`.
func IsOurs(ep hubble.Endpoint, label, namespace string) bool {
	return labels.HasLabel(ep.Labels, label) && epNamespace(ep) == namespace
}

// ExtractConnections builds a ConnGraph from raw Hubble flows. `label` (a
// "key=value" pod label) plus `namespace` together identify "our" pods — the
// same namespace the generated policy will be deployed into.
func ExtractConnections(flows []*hubble.Flow, label, namespace string) *model.ConnGraph {
	graph := model.NewConnGraph()
	MergeConnections(graph, flows, label, namespace)
	return graph
}

// MergeConnections folds flows into an existing ConnGraph. Lets a caller
// accumulate connections across many small flow batches (e.g. one per audit
// round) without keeping the raw flows around: graph's size is bounded by
// the number of distinct (src,dst,port,proto) tuples ever seen, not by
// traffic volume.
func MergeConnections(graph *model.ConnGraph, flows []*hubble.Flow, label, namespace string) {
	ourApp := labels.LabelToApp(label)
	for _, flow := range flows {
		c, reason := classify(flow, label, namespace, ourApp)
		if reason != "" {
			if reason == reasonNoApp {
				ui.Log("Skipping flow with missing app labels: src=%q dst=%q", c.src.App, c.dst.App)
			}
			continue
		}
		switch {
		case c.external:
			graph.Bucket(c.src.App, c.src.Namespace).EgressExternal[model.ExtConn{IP: c.ip, Port: c.port, Proto: c.proto}]++
		case c.egress:
			graph.Bucket(c.src.App, c.src.Namespace).EgressApps[model.AppConn{Peer: c.dst, Port: c.port, Proto: c.proto}]++
		}
		if c.ingress {
			graph.Bucket(c.dst.App, c.dst.Namespace).IngressApps[model.AppConn{Peer: c.src, Port: c.port, Proto: c.proto}]++
		}
	}
}

// Reasons classify gives for a flow that makes no rule.
const (
	reasonIgnored = "ignored"
	reasonNoApp   = "no app identity"
	// NoIdentity is the reason for traffic into our pods from an IP Cilium
	// had no identity for (reserved:world): an external client, or a pod the
	// node hadn't learned about yet (e.g. a short-lived Job pod). Neither can
	// be selected by a stable rule, so it's left to the operator.
	NoIdentity = "source has no Cilium identity (reserved:world)"
	// NotSelectable is the reason for traffic into our pods from a reserved
	// identity that isn't a Cilium entity (e.g. reserved:unknown).
	NotSelectable = "source is a reserved identity no rule can select"
)

type conn struct {
	src, dst                  model.Endpoint
	port                      int32
	proto                     string
	ip                        string // external destination IP, when external
	egress, external, ingress bool
}

// classify works out which rules a flow makes. reason is non-empty when it
// makes none.
func classify(flow *hubble.Flow, label, namespace, ourApp string) (conn, string) {
	var c conn
	if flow == nil || flow.IsReply {
		return c, reasonIgnored
	}
	// SOCK-layer flows are pre-translation/pre-policy-decision socket
	// observations that report a generic identity for traffic a later
	// L3_L4/TO_STACK/TO_ENDPOINT flow already captures correctly. Including
	// them produces duplicate, wrongly-scoped, or overly broad rules.
	if flow.Type == "SOCK" {
		return c, reasonIgnored
	}

	src, dst := flow.Source, flow.Destination
	srcOurs := IsOurs(src, label, namespace)
	dstOurs := IsOurs(dst, label, namespace)
	if !srcOurs && !dstOurs {
		return c, reasonIgnored
	}
	srcNS, dstNS := epNamespace(src), epNamespace(dst)
	// Our pods are identified by the -l label itself, not by whichever app
	// label GetApp picks: that names the policy and is its endpointSelector,
	// and an app label like app.kubernetes.io/name may be shared with pods
	// outside the audited set (e.g. other instances of the same chart).
	srcApp := labels.GetApp(src.Labels)
	if srcOurs && ourApp != "" {
		srcApp = ourApp
	}
	c.port, c.proto = flow.Port()
	dstApp := labels.GetPeerApp(dst.Labels, c.port)
	if dstOurs && ourApp != "" {
		dstApp = ourApp
	}
	// A pod with no app label (e.g. a CronJob's) is selected by one of its
	// own stable labels, or its namespace, as verify does.
	if srcApp == "" && !isReserved(src) {
		srcApp = labels.FallbackSelector(src.Labels, srcNS)
	}
	if dstApp == "" && !isReserved(dst) {
		dstApp = labels.FallbackSelector(dst.Labels, dstNS)
	}
	c.src = model.Endpoint{App: srcApp, Namespace: srcNS}
	c.dst = model.Endpoint{App: dstApp, Namespace: dstNS}
	if srcApp == "" || dstApp == "" {
		return c, reasonNoApp
	}

	// Egress: source is one of our target pods.
	if srcOurs {
		if dstApp == "reserved:world" {
			c.external = true
			c.ip = flow.DstIP()
			if c.ip == "" {
				c.ip = "UNKNOWN"
			}
		} else {
			c.egress = true
		}
	}

	// Ingress: destination is one of our target pods. Reserved sources are
	// allowed by fromEntities, when they are a Cilium entity, except the
	// local host: Cilium always lets it reach local pods (allow-localhost),
	// so kubelet probes need no rule.
	if dstOurs && !strings.HasPrefix(dstApp, "reserved:") {
		switch {
		case srcApp == "reserved:host":
			return c, reasonIgnored
		case srcApp == "reserved:world":
			return c, NoIdentity
		case strings.HasPrefix(srcApp, "reserved:"):
			if _, ok := labels.Entity(srcApp); !ok {
				return c, NotSelectable
			}
			c.src.Namespace = ""
			c.ingress = true
		default:
			c.ingress = true
		}
	}
	return c, ""
}

// Unusable says why a flow makes no rule for the pods label and namespace
// select, or "" when it makes one. Audit uses it to tell traffic still
// missing from the policy from traffic no generated rule can allow.
func Unusable(flow *hubble.Flow, label, namespace string) string {
	_, reason := classify(flow, label, namespace, labels.LabelToApp(label))
	return reason
}

func isReserved(ep hubble.Endpoint) bool {
	for _, l := range ep.Labels {
		if strings.HasPrefix(l, "reserved:") {
			return true
		}
	}
	return false
}

// LoadFlowsFile loads flows from a file, accepting either a JSON array or
// NDJSON (one flow per line).
func LoadFlowsFile(path string) ([]*hubble.Flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	head, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	if head[0] == '[' {
		// JSON array of wrapped or bare flows.
		var raw []json.RawMessage
		if err := json.NewDecoder(r).Decode(&raw); err != nil {
			return nil, err
		}
		flows := make([]*hubble.Flow, 0, len(raw))
		for _, item := range raw {
			fl, err := hubble.ParseLine(item)
			if err != nil || fl == nil {
				continue
			}
			flows = append(flows, fl)
		}
		return flows, nil
	}

	var flows []*hubble.Flow
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fl, err := hubble.ParseLine([]byte(line))
		if err != nil || fl == nil {
			continue
		}
		flows = append(flows, fl)
	}
	return flows, sc.Err()
}

// observeCmd builds the `hubble observe` argv. Hubble ORs repeated --label
// filters, so the stream carries flows from or to pods with any of labels;
// no labels watches every pod.
func observeCmd(labels []string, last int, follow bool, cel string) []string {
	cmd := []string{"hubble", "observe", "--output", "json"}
	for _, label := range labels {
		cmd = append(cmd, "--label", label)
	}
	if cel != "" {
		cmd = append(cmd, "--cel-expression", cel)
	}
	if follow {
		cmd = append(cmd, "--follow")
	} else if last > 0 {
		cmd = append(cmd, "--last", strconv.Itoa(last))
	}
	return cmd
}

// CollectLast collects the last N flows per Cilium pod (batch mode). `cel` may
// be "" for no filter.
func CollectLast(ctx context.Context, k *kube.Client, label string, last int, cel string) ([]*hubble.Flow, error) {
	pods, err := k.CiliumPods(ctx)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		ui.Warn("No cilium pods found.")
		return nil, nil
	}

	argv := observeCmd(nonEmpty(label), last, false, cel)

	var (
		mu       sync.Mutex
		allFlows []*hubble.Flow
		realSeen bool
	)
	var wg sync.WaitGroup
	for _, pod := range pods {
		wg.Add(1)
		go func(pod kube.Pod) {
			defer wg.Done()
			out, errOut, err := k.Exec(ctx, pod.Name, argv)
			if err != nil {
				ui.Warn("%s (%s): %v", pod.Name, pod.Node, err)
			}
			var local []*hubble.Flow
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				fl, perr := hubble.ParseLine([]byte(line))
				if perr != nil || fl == nil {
					continue
				}
				local = append(local, fl)
			}
			if s := strings.TrimSpace(errOut); s != "" {
				ui.Warn("%s (%s): %s", pod.Name, pod.Node, lastLine(s))
			}
			ui.Log("%s (%s): %d flows", pod.Name, pod.Node, len(local))
			mu.Lock()
			allFlows = append(allFlows, local...)
			if len(local) > 0 {
				realSeen = true
			}
			mu.Unlock()
		}(pod)
	}
	wg.Wait()

	ui.Log("Collected %d flows total from %d pods", len(allFlows), len(pods))
	if !realSeen {
		ui.Warn("0 real flows collected for label=%q: check the label matches "+
			"running pods, or that traffic occurred during the observed window. "+
			"Generating from an empty flow set produces 0 policies, which is not "+
			"the same as convergence.", label)
	}
	return allFlows, nil
}

// nonEmpty returns label as a one-element list, or nil for "" (every pod).
func nonEmpty(label string) []string {
	if label == "" {
		return nil
	}
	return []string{label}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

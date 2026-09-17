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
	"errors"
	"fmt"
	"io"
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

// hasLabel reports whether lbls contains the exact "key=value" pair given by
// filter (e.g. "app.kubernetes.io/name=foo"), with or without Cilium's "k8s:"
// prefix.
func hasLabel(lbls []string, filter string) bool {
	key, val, ok := strings.Cut(filter, "=")
	if !ok {
		return false
	}
	key, val = strings.TrimSpace(key), strings.TrimSpace(val)
	want1 := key + "=" + val
	want2 := "k8s:" + key + "=" + val
	for _, l := range lbls {
		if l == want1 || l == want2 {
			return true
		}
	}
	return false
}

func epNamespace(ep hubble.Endpoint) string {
	// Hubble usually sets a top-level namespace, but it's sometimes absent even
	// though the labels carry it, so fall back so pods aren't split into a
	// namespace="" bucket.
	if ep.Namespace != "" {
		return ep.Namespace
	}
	return labels.GetNamespace(ep.Labels)
}

// isOurs reports whether an endpoint is one of the target pods: matching both
// `label` and `namespace`.
func isOurs(ep hubble.Endpoint, label, namespace string) bool {
	return hasLabel(ep.Labels, label) && epNamespace(ep) == namespace
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
	for _, flow := range flows {
		if flow == nil || flow.IsReply {
			continue
		}
		// SOCK-layer flows are pre-translation/pre-policy-decision socket
		// observations that report a generic identity for traffic a later
		// L3_L4/TO_STACK/TO_ENDPOINT flow already captures correctly. Including
		// them produces duplicate, wrongly-scoped, or overly broad rules.
		if flow.Type == "SOCK" {
			continue
		}

		src, dst := flow.Source, flow.Destination
		srcApp := labels.GetApp(src.Labels)
		dstApp := labels.GetApp(dst.Labels)
		if srcApp == "" || dstApp == "" {
			ui.Log("Skipping flow with missing app labels: src=%q dst=%q", srcApp, dstApp)
			continue
		}

		srcNS := epNamespace(src)
		dstNS := epNamespace(dst)
		port, proto := flow.Port()

		srcKey := model.Endpoint{App: srcApp, Namespace: srcNS}
		dstKey := model.Endpoint{App: dstApp, Namespace: dstNS}

		// Egress: source is one of our target pods.
		if isOurs(src, label, namespace) {
			bucket := graph.Bucket(srcApp, srcNS)
			if dstApp == "reserved:world" {
				ip := flow.DstIP()
				if ip == "" {
					ip = "UNKNOWN"
				}
				bucket.EgressExternal[model.ExtConn{IP: ip, Port: port, Proto: proto}]++
			} else {
				bucket.EgressApps[model.AppConn{Peer: dstKey, Port: port, Proto: proto}]++
			}
		}

		// Ingress: destination is one of our target pods (skip reserved src/dst).
		if isOurs(dst, label, namespace) &&
			!strings.HasPrefix(dstApp, "reserved:") &&
			!strings.HasPrefix(srcApp, "reserved:") {
			bucket := graph.Bucket(dstApp, dstNS)
			bucket.IngressApps[model.AppConn{Peer: srcKey, Port: port, Proto: proto}]++
		}
	}
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

// observeCmd builds the `hubble observe` argv.
func observeCmd(label string, last int, follow bool, cel string) []string {
	cmd := []string{"hubble", "observe", "--output", "json", "--label", label}
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

	argv := observeCmd(label, last, false, cel)

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

// Follower keeps exactly one unfiltered `hubble observe --follow` exec alive
// per Cilium pod for as long as ctx lives. Every parsed flow is pushed to
// onFlow as it arrives; callers that need a bounded window (e.g. one audit
// round) filter/collect from onFlow themselves rather than starting a new
// exec per window.
type Follower struct {
	wg   sync.WaitGroup
	errs []error
	mu   sync.Mutex
}

// StartFollow starts the persistent per-pod streams and returns immediately;
// call Wait to block until ctx is cancelled and every stream has torn down.
func StartFollow(ctx context.Context, k *kube.Client, label string, onFlow func(*hubble.Flow)) (*Follower, error) {
	pods, err := k.CiliumPods(ctx)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		ui.Warn("No cilium pods found.")
		return &Follower{}, nil
	}

	argv := observeCmd(label, 0, true, "")
	f := &Follower{}
	for _, pod := range pods {
		f.wg.Add(1)
		go func(pod kube.Pod) {
			defer f.wg.Done()
			pr, pw := io.Pipe()
			done := make(chan struct{})
			go func() {
				sc := bufio.NewScanner(pr)
				sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" {
						continue
					}
					fl, perr := hubble.ParseLine([]byte(line))
					if perr != nil || fl == nil {
						continue
					}
					onFlow(fl)
				}
				close(done)
			}()
			err := k.ExecStream(ctx, pod.Name, argv, pw)
			pw.Close()
			<-done
			// ExecStream's context cancellation closes cnpgen's side of the
			// connection but does not, by itself, terminate the exec'd
			// process on the agent: with no TTY there's no pty hangup, and
			// `hubble observe --follow` doesn't exit on its own when its
			// stdout pipe goes away. Explicitly kill it so it doesn't run
			// forever as an orphan.
			k.KillMatching(pod.Name, argv)
			if err != nil {
				f.mu.Lock()
				f.errs = append(f.errs, fmt.Errorf("%s: %w", pod.Name, err))
				f.mu.Unlock()
			}
		}(pod)
	}
	return f, nil
}

// Wait blocks until every per-pod stream has torn down (i.e. until the ctx
// passed to StartFollow is cancelled) and returns any exec errors joined
// together.
func (f *Follower) Wait() error {
	f.wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	return errors.Join(f.errs...)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

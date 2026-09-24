// Package verifycmd runs a read-only watch loop against whatever
// CiliumNetworkPolicy is already deployed for a target - cnpgen's own, hand
// written, or from any other tool. It never generates, deploys, or deletes
// anything: it just watches live traffic, reports what the current policy
// does not allow (policy_match_type == 4, computed by Cilium itself against
// whatever policy is actually live), and suggests an egress snippet for each
// distinct missing connection.
package verifycmd

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kwistof/cnpgen/internal/collect"
	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/pipeline"
	"github.com/kwistof/cnpgen/internal/resolve"
	"github.com/kwistof/cnpgen/internal/ui"
	"github.com/kwistof/cnpgen/internal/verify"
)

// Config holds the verify run parameters.
type Config struct {
	Label     string
	Namespace string
	Settle    int // stop after this many stable rounds in a row; 0 = never auto-stop
	Duration  time.Duration
	FqdnDump  string
}

// Run executes the verify loop: watch -> report -> repeat, until Ctrl+C or
// --settle stable rounds. It never writes to the cluster.
func Run(ctx context.Context, k *kube.Client, cfg Config) error {
	autoStop := cfg.Settle > 0
	fmt.Println(ui.Bold(fmt.Sprintf("Verifying %s.", pipeline.DescribeTarget(cfg.Label, cfg.Namespace))))
	fmt.Println(ui.Dim("  Read-only: watches live traffic against whatever CiliumNetworkPolicy is " +
		"already deployed, reports what it doesn't allow. Never generates, deploys, or deletes anything."))
	if autoStop {
		fmt.Println(ui.Dim(fmt.Sprintf("  Watching %s per round. Stops after %d stable round(s) in a row, or Ctrl+C.", cfg.Duration, cfg.Settle)))
	} else {
		fmt.Println(ui.Dim(fmt.Sprintf("  Watching %s per round, until Ctrl+C.", cfg.Duration)))
	}

	if n, err := k.CountPodsMatching(ctx, cfg.Label, cfg.Namespace); err != nil {
		ui.Warn("checking for matching pods: %v", err)
	} else if n == 0 {
		fmt.Println(ui.Yellow(fmt.Sprintf(
			"  Warning: no pods matching %s right now. Watching anyway in case they appear later; "+
				"if that's not expected, check the label and namespace.", pipeline.DescribeTarget(cfg.Label, cfg.Namespace))))
	} else {
		fmt.Println(ui.Dim(fmt.Sprintf("  %d pod(s) matching %s.", n, pipeline.DescribeTarget(cfg.Label, cfg.Namespace))))
	}

	dropWindow := verify.NewWindow(true)
	follower, err := collect.StartFollow(ctx, k, cfg.Label, dropWindow.OnFlow)
	if err != nil {
		return fmt.Errorf("starting flow watch: %w", err)
	}

	index := resolveIndex(ctx, k, cfg.FqdnDump)

	stableStreak := 0
	interrupted := false
	rnd := 0
	for {
		rnd++
		if ctx.Err() != nil {
			interrupted = true
			break
		}

		fmt.Println(ui.Cyan(fmt.Sprintf("\n== Round %d ==", rnd)))
		fmt.Printf("  Watching %s...\n", cfg.Duration)

		dropFlows, werr := dropWindow.Wait(ctx, cfg.Duration)
		if errors.Is(werr, context.Canceled) {
			interrupted = true
			break
		}

		counter := verify.SummarizeDrops(dropFlows)
		verify.PrintDropSummary(counter)
		printSuggestions(dropFlows, index)

		if len(counter) == 0 {
			stableStreak++
			if autoStop && stableStreak >= cfg.Settle {
				fmt.Println(ui.Green(fmt.Sprintf("  Settled: %d stable round(s) in a row, nothing missing.", cfg.Settle)))
				break
			}
			if autoStop {
				fmt.Println(ui.Green(fmt.Sprintf("  Stable (%d/%d).", stableStreak, cfg.Settle)) +
					ui.Dim(" Still watching, Ctrl+C to stop."))
			} else {
				fmt.Println(ui.Green("  Stable for now.") + ui.Dim(" Still watching, Ctrl+C to stop."))
			}
			continue
		}
		stableStreak = 0
	}

	if interrupted {
		fmt.Println(ui.Dim("\nStopped (Ctrl+C)."))
	}

	if err := follower.Wait(); err != nil {
		ui.Warn("flow watch: %v", err)
	}
	return nil
}

// resolveIndex builds a resolve index for turning suggestion destinations
// into FQDNs where possible: the live FQDN cache (or a saved dump), plus
// whatever destination_names this run's own flows carry.
func resolveIndex(ctx context.Context, k *kube.Client, fqdnDump string) *model.ResolveIndex {
	var sources []resolve.Source
	if fqdnDump != "" {
		if m, err := resolve.FqdnCacheFromDump(fqdnDump); err == nil {
			sources = append(sources, resolve.Source{Name: "fqdn-cache", Map: m})
		} else {
			ui.Warn("reading --fqdn-cache %s: %v", fqdnDump, err)
		}
	} else if m, err := resolve.FqdnCacheLive(ctx, k); err == nil {
		sources = append(sources, resolve.Source{Name: "fqdn-cache", Map: m})
	} else {
		ui.Warn("fetching live FQDN cache: %v", err)
	}
	return resolve.BuildIndex(sources, nil)
}

// suggestKey identifies one distinct missing egress rule: same destination,
// port, and protocol as would appear in a generated policy.
type suggestKey struct {
	dst   string // toFQDNs matchName | toEndpoints app label value | toCIDR
	kind  string // "fqdn" | "endpoint" | "cidr"
	ns    string // destination namespace, endpoint kind only
	port  int32
	proto string
}

// printSuggestions renders one egress snippet per distinct missing
// connection seen in dropFlows, most-recently-collected order suppressed in
// favor of a stable sort so repeated rounds print in the same order.
func printSuggestions(dropFlows []*hubble.Flow, index *model.ResolveIndex) {
	seen := map[suggestKey]bool{}
	var keys []suggestKey
	for _, f := range dropFlows {
		if f == nil {
			continue
		}
		k := classifyDestination(f, index)
		if k.dst == "" {
			continue
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		if keys[i].dst != keys[j].dst {
			return keys[i].dst < keys[j].dst
		}
		return keys[i].port < keys[j].port
	})

	fmt.Println(ui.Dim("  Suggested egress, add to your policy's `egress` list:"))
	for _, k := range keys {
		for _, line := range snippet(k) {
			fmt.Println(ui.Dim("    " + line))
		}
	}
}

// classifyDestination picks the best available identity for a flow's
// destination: a resolved FQDN first, a same-cluster app label second,
// otherwise the raw destination IP as a CIDR.
func classifyDestination(f *hubble.Flow, index *model.ResolveIndex) suggestKey {
	port, proto := f.Port()
	if proto == "" {
		return suggestKey{}
	}

	if app := labels.GetApp(f.Destination.Labels); app != "" && !strings.HasPrefix(app, "reserved:") {
		ns := f.Destination.Namespace
		if ns == "" {
			ns = labels.GetNamespace(f.Destination.Labels)
		}
		return suggestKey{dst: app, kind: "endpoint", ns: ns, port: port, proto: proto}
	}

	ip := f.DstIP()
	if ip == "" {
		return suggestKey{}
	}
	if index != nil {
		if rf := index.ResolvedFor(ip); rf != nil && rf.Resolved() {
			for fqdn := range rf.Fqdns {
				return suggestKey{dst: fqdn, kind: "fqdn", port: port, proto: proto}
			}
		}
	}
	for _, name := range f.DestinationNames {
		if name != "" {
			return suggestKey{dst: name, kind: "fqdn", port: port, proto: proto}
		}
	}
	cidr := ip
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	return suggestKey{dst: cidr, kind: "cidr", port: port, proto: proto}
}

// snippet renders one YAML-ish egress rule fragment for a suggestKey.
func snippet(k suggestKey) []string {
	ports := []string{
		"toPorts:",
		fmt.Sprintf("  - ports: [{port: %q, protocol: %s}]", fmt.Sprintf("%d", k.port), k.proto),
	}
	switch k.kind {
	case "fqdn":
		return append([]string{
			"- toFQDNs:",
			fmt.Sprintf("    - matchName: %q", k.dst),
		}, indent(ports, "  ")...)
	case "endpoint":
		sel := labels.AppToLabelSelector(k.dst)
		var ml []string
		for key, val := range sel {
			ml = append(ml, fmt.Sprintf("%s: %s", key, val))
		}
		sort.Strings(ml)
		if k.ns != "" {
			ml = append(ml, "io.kubernetes.pod.namespace: "+k.ns)
		}
		return append([]string{
			"- toEndpoints:",
			fmt.Sprintf("    - matchLabels: {%s}", strings.Join(ml, ", ")),
		}, indent(ports, "  ")...)
	default: // cidr
		return append([]string{
			"- toCIDR:",
			fmt.Sprintf("    - %s", k.dst),
		}, indent(ports, "  ")...)
	}
}

func indent(lines []string, prefix string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = prefix + l
	}
	return out
}

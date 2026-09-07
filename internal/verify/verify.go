// Package verify observes would-be-dropped flows (policy_match_type == 4) for a
// target.
//
// With enableDefaultDeny:false policies deployed, any flow still reporting
// policy_match_type == 4 is traffic the policy does NOT yet allow: a missing
// rule. VerifyWindow returns those flows so the audit loop can feed them back
// through ExtractConnections.
package verify

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kwistof/cnpgen/internal/collect"
	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/ui"
)

// DropCEL selects flows Cilium would drop under an enforcing policy.
const DropCEL = "_flow.policy_match_type == uint(4)"

// VerifyWindow streams flows for `duration`, returning the collected flows.
// `cel` defaults to the would-be-dropped filter; pass "" to stream every flow
// (used when there's no deployed policy yet). It stops early if the parent ctx
// is cancelled (e.g. Ctrl+C), returning ctx.Err() so the caller can stop
// looping.
func VerifyWindow(ctx context.Context, k *kube.Client, label string, duration time.Duration, cel string) ([]*hubble.Flow, error) {
	windowCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var (
		mu        sync.Mutex
		collected []*hubble.Flow
	)
	onFlow := func(f *hubble.Flow) {
		mu.Lock()
		collected = append(collected, f)
		mu.Unlock()
	}

	err := collect.StreamFollow(windowCtx, k, label, cel, onFlow)

	kind := "would-be-dropped"
	if cel == "" {
		kind = "observed"
	}
	ui.Log("VerifyWindow: %d %s flows in %s", len(collected), kind, duration)

	if ctx.Err() != nil {
		// The parent (not just the window timeout) was cancelled, so surface it.
		return collected, ctx.Err()
	}
	return collected, err
}

// DropKey identifies a distinct would-be-dropped connection.
type DropKey struct {
	SrcApp, SrcNS, DstApp, DstNS string
	Port                         int32
	Proto                        string
}

// SummarizeDrops counts flows by (src, dst, port, proto).
func SummarizeDrops(flows []*hubble.Flow) map[DropKey]int {
	counter := map[DropKey]int{}
	for _, flow := range flows {
		if flow == nil {
			continue
		}
		src, dst := flow.Source, flow.Destination
		srcApp := labels.GetApp(src.Labels)
		if srcApp == "" {
			srcApp = flow.SrcIP()
		}
		if srcApp == "" {
			srcApp = "?"
		}
		dstApp := labels.GetApp(dst.Labels)
		if dstApp == "" || dstApp == "reserved:world" {
			dstApp = flow.DstIP()
			if dstApp == "" {
				dstApp = "?"
			}
		}
		port, proto := flow.Port()
		srcNS := src.Namespace
		if srcNS == "" {
			srcNS = labels.GetNamespace(src.Labels)
		}
		if srcNS == "" {
			srcNS = "?"
		}
		dstNS := dst.Namespace
		if dstNS == "" {
			dstNS = labels.GetNamespace(dst.Labels)
		}
		if dstNS == "" {
			dstNS = "?"
		}
		counter[DropKey{srcApp, srcNS, dstApp, dstNS, port, proto}]++
	}
	return counter
}

// PrintDropSummary prints a drop summary, most-frequent first.
func PrintDropSummary(counter map[DropKey]int) {
	if len(counter) == 0 {
		fmt.Println(ui.Green("  Nothing would be dropped."))
		return
	}
	total := 0
	for _, c := range counter {
		total += c
	}
	fmt.Println(ui.Yellow(fmt.Sprintf("  %d would-be-dropped (%d distinct):", total, len(counter))))

	type row struct {
		k DropKey
		c int
	}
	rows := make([]row, 0, len(counter))
	for k, c := range counter {
		rows = append(rows, row{k, c})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].c > rows[j].c })
	for _, r := range rows {
		k := r.k
		fmt.Printf("    %4dx  %s (%s) -> %s (%s)  port=%d/%s\n",
			r.c, k.SrcApp, k.SrcNS, k.DstApp, k.DstNS, k.Port, k.Proto)
	}
}

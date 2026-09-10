// Package verify observes would-be-dropped flows (policy_match_type == 4) for a
// target.
//
// With enableDefaultDeny:false policies deployed, any flow still reporting
// policy_match_type == 4 is traffic the policy does NOT yet allow: a missing
// rule. Window collects those flows (from a flow feed the caller already has
// running, see collect.Follower) so the audit loop can feed them back through
// ExtractConnections.
package verify

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/ui"
)

// dropped reports whether Cilium would drop this flow under an enforcing
// policy.
func dropped(f *hubble.Flow) bool {
	return f.PolicyMatchType == 4
}

// Window collects flows from an already-running flow feed (see
// collect.StartFollow) for `duration`, optionally keeping only would-be-dropped
// flows.
type Window struct {
	mu        sync.Mutex
	collected []*hubble.Flow
	dropOnly  bool
}

// NewWindow returns a Window ready to receive flows via OnFlow. When dropOnly
// is true, only would-be-dropped flows (policy_match_type == 4) are kept;
// otherwise every flow is kept.
func NewWindow(dropOnly bool) *Window {
	return &Window{dropOnly: dropOnly}
}

// OnFlow is the callback to pass to the shared flow feed (collect.Follower).
func (w *Window) OnFlow(f *hubble.Flow) {
	if w.dropOnly && !dropped(f) {
		return
	}
	w.mu.Lock()
	w.collected = append(w.collected, f)
	w.mu.Unlock()
}

// Reset clears collected flows so the same Window can be reused for the next
// round without a new subscription.
func (w *Window) Reset() {
	w.mu.Lock()
	w.collected = nil
	w.mu.Unlock()
}

// Snapshot returns the flows collected so far.
func (w *Window) Snapshot() []*hubble.Flow {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*hubble.Flow(nil), w.collected...)
}

// Wait blocks for `duration` or until ctx is cancelled, then returns the
// flows collected during that time (via Reset beforehand to scope it to just
// this call). It stops early if ctx is cancelled (e.g. Ctrl+C), returning
// ctx.Err() so the caller can stop looping.
func (w *Window) Wait(ctx context.Context, duration time.Duration) ([]*hubble.Flow, error) {
	w.Reset()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return w.Snapshot(), ctx.Err()
	}

	collected := w.Snapshot()
	kind := "observed"
	if w.dropOnly {
		kind = "would-be-dropped"
	}
	ui.Log("Window: %d %s flows in %s", len(collected), kind, duration)
	return collected, nil
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

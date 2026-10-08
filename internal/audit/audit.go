// Package audit runs the deploy -> verify -> diff -> regenerate loop.
//
// The loop converges when a verify window observes no new (src,dst,port,proto)
// tuples. On convergence it prunes the temporary DNS rule from policies that
// ended up with no toFQDNs and writes the final policy set. It NEVER flips
// enableDefaultDeny to true: that stays a deliberate manual step.
package audit

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/kwistof/cnpgen/internal/collect"
	"github.com/kwistof/cnpgen/internal/deploy"
	"github.com/kwistof/cnpgen/internal/generate"
	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/pipeline"
	"github.com/kwistof/cnpgen/internal/resolve"
	"github.com/kwistof/cnpgen/internal/settings"
	"github.com/kwistof/cnpgen/internal/ui"
	"github.com/kwistof/cnpgen/internal/verify"
)

// Config holds the audit run parameters.
type Config struct {
	// Labels are the pods to watch, one policy set each: several labels
	// share one flow stream per Cilium agent instead of one per label.
	Labels    []string
	Namespace string
	OutDir    string
	Settle    int // stop after this many stable rounds in a row; 0 = never auto-stop
	Duration  time.Duration
	Accept    bool
	DryRun    bool
	FqdnDump  string
	Seed      *generate.Seed // from --seed-policy (single label only); merged into every round as a floor
}

// target is the per-label state of a run: what `cnpgen audit -l <label>`
// would track on its own.
type target struct {
	label string
	// graph is this label's persistent state, accumulated round over round
	// by folding in each round's flow batch (collect.MergeConnections) rather
	// than keeping every flow ever seen: an audit run has no natural end (the
	// Helm chart always sets Settle=0), so retaining raw flows for the run's
	// whole lifetime grows without bound and eventually OOMs. It is instead
	// bounded by the number of distinct connections ever observed, not by
	// traffic volume.
	graph    *model.ConnGraph
	policies []*generate.Policy
	// bootstrapDNSAttempted tracks whether a deploy of the standalone DNS
	// policy was ever attempted, not whether it's known to have succeeded: a
	// Ctrl+C can make an apply look like it failed client-side ("context
	// canceled") while the write still lands server-side, so treat
	// "attempted" as the safe signal for cleanup and let the delete be a
	// no-op when there's nothing there.
	bootstrapDNSAttempted bool
	bootstrapping         bool   // no app policy yet: this round watches all its traffic
	lastSig               string // previous round's pipeline.Signature(policies), for dedup
	lastApply             string // signature at the time policies were last actually applied
	seenNotes             map[string]struct{}
	stableStreak          int  // consecutive rounds with no new blocked traffic
	done                  bool // settled (or dry-run): finalized, out of the loop
}

// resolveIndex builds the resolve index. fqdnIPs is the audit loop's
// persistent, round-over-round accumulation of fqdn->ips pairs seen in flow
// L7 data (see collect.MergeConnections's sibling resolve.MergeFqdnFromFlows)
// rather than the raw flows themselves.
func resolveIndex(ctx context.Context, k *kube.Client, cfg settings.Settings, fqdnIPs map[string]map[string]struct{}, fqdnDump string) *model.ResolveIndex {
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
	sources = append(sources, resolve.Source{Name: "flow-l7", Map: fqdnIPs})
	return resolve.BuildIndex(sources, cfg.KnownIPs)
}

func applyFlag(ok, skipped bool) string {
	if skipped {
		return ui.Yellow("skip")
	}
	if ok {
		return ui.Green("ok")
	}
	return ui.Red("FAIL")
}

// Run executes the audit loop and returns the final policies.
//
// The loop always runs until stopped: either the user interrupts it (Ctrl+C),
// or, when ac.Settle > 0, it auto-stops once that many rounds in a row see no
// new blocked traffic. Either way, the deployed (non-enforcing) policy is
// removed from the cluster at the end; the generated policy file is kept.
//
// With several labels, each one goes through the same loop as if audited
// alone (its own policies, bootstrap DNS policy, stable streak and teardown;
// one settling stops and cleans up just that one), but the rounds run in
// step so they all drain one shared flow stream.
func Run(ctx context.Context, k *kube.Client, cfg settings.Settings, ac Config, initialFlows []*hubble.Flow) ([]*generate.Policy, error) {
	autoStop := ac.Settle > 0
	multi := len(ac.Labels) > 1
	what := pipeline.DescribeTarget(ac.Labels[0], ac.Namespace)
	if multi {
		what = fmt.Sprintf("%d labels in %s", len(ac.Labels), ac.Namespace)
	}
	fmt.Println(ui.Bold(fmt.Sprintf("Auditing %s.", what)))
	if autoStop {
		fmt.Println(ui.Dim(fmt.Sprintf("  Generate -> deploy (safe mode) -> watch %s -> repeat. "+
			"Stops after %d stable round(s) in a row, or Ctrl+C.", ac.Duration, ac.Settle)))
	} else {
		fmt.Println(ui.Dim(fmt.Sprintf("  Generate -> deploy (safe mode) -> watch %s -> repeat, until Ctrl+C.", ac.Duration)))
	}

	for _, label := range ac.Labels {
		desc := pipeline.DescribeTarget(label, ac.Namespace)
		if n, err := k.CountPodsMatching(ctx, label, ac.Namespace); err != nil {
			ui.Warn("checking for matching pods: %v", err)
		} else if n == 0 {
			fmt.Println(ui.Yellow(fmt.Sprintf(
				"  Warning: no pods matching %s right now. Watching anyway in case they appear later; "+
					"if that's not expected, check the label and namespace.", desc)))
		} else {
			fmt.Println(ui.Dim(fmt.Sprintf("  %d pod(s) matching %s.", n, desc)))
		}
	}

	// One persistent, unfiltered `hubble observe --follow` exec per Cilium
	// pod for the whole run, for every label at once: every round drains
	// this same feed rather than opening its own exec session.
	// allFlowsWindow and dropFlowsWindow both subscribe to it;
	// dropFlowsWindow applies the would-be-dropped filter client-side, and
	// each label then takes its own share of both (forLabel).
	//
	// allFlowsWindow is only drained while some label has no policy yet (the
	// bootstrap branch below). A label never loses its policy once it has
	// one, so once every label has one nothing reads allFlowsWindow again for
	// the rest of the run, and needsAllFlows gates the callback to stop
	// feeding it — otherwise it would collect every flow for the run's entire
	// remaining (unbounded) lifetime with nothing ever draining it, growing
	// forever.
	var needsAllFlows atomic.Bool
	needsAllFlows.Store(true)
	followCtx, stopFollow := context.WithCancel(ctx)
	defer stopFollow()
	allFlowsWindow := verify.NewWindow(false)
	dropFlowsWindow := verify.NewWindow(true)
	follower, err := collect.StartFollow(followCtx, k, ac.Labels, func(f *hubble.Flow) {
		if needsAllFlows.Load() {
			allFlowsWindow.OnFlow(f)
		}
		dropFlowsWindow.OnFlow(f)
	})
	if err != nil {
		return nil, fmt.Errorf("starting flow watch: %w", err)
	}

	// forLabel keeps the flows the label's own `hubble observe --label`
	// would have streamed: from or to one of its pods.
	forLabel := func(flows []*hubble.Flow, label string) []*hubble.Flow {
		if !multi {
			return flows
		}
		var mine []*hubble.Flow
		for _, f := range flows {
			if labels.HasLabel(f.Source.Labels, label) || labels.HasLabel(f.Destination.Labels, label) {
				mine = append(mine, f)
			}
		}
		return mine
	}
	// heading starts a label's section of the round's output.
	heading := func(t *target) {
		if multi {
			fmt.Println(ui.Bold("  [" + t.label + "]"))
		}
	}

	// fqdnIPs accumulates fqdn->ips pairs seen in flow L7 data, round over
	// round (resolve.MergeFqdnFromFlows), for the same reason as
	// target.graph. Name resolution isn't per app, so labels share it.
	fqdnIPs := map[string]map[string]struct{}{}
	resolve.MergeFqdnFromFlows(fqdnIPs, initialFlows)
	targets := make([]*target, len(ac.Labels))
	for i, label := range ac.Labels {
		t := &target{label: label, graph: model.NewConnGraph(), seenNotes: map[string]struct{}{}}
		collect.MergeConnections(t.graph, initialFlows, label, ac.Namespace)
		targets[i] = t
	}
	generateFor := func(t *target, index *model.ResolveIndex) {
		t.policies = pipeline.GeneratePoliciesFromGraph(t.graph, ac.Namespace, index, cfg, ac.Accept, true, false, ac.Seed)
	}
	// finish finalizes a target and removes what it deployed (cleanup uses
	// a fresh, non-cancelled context so Ctrl+C doesn't abort the teardown).
	finish := func(t *target) {
		t.done = true
		if multi {
			fmt.Println(ui.Cyan(fmt.Sprintf("\n== %s ==", t.label)))
		}
		finalize(t.policies, ac.OutDir)
		cleanupCtx := context.Background()
		if t.bootstrapDNSAttempted {
			fmt.Println(ui.Dim("\nRemoving temporary DNS visibility (no app policy took over):"))
			removeBootstrapDNS(cleanupCtx, k, ac.Namespace, t.label)
		}
		// Always tidy up the non-enforcing policy we deployed while learning;
		// the generated file is what you keep and apply (with enforcement)
		// yourself. Nothing was deployed under --dry-run, so there's nothing
		// to remove.
		if !ac.DryRun {
			fmt.Println(ui.Cyan("\nRemoving the policy from the cluster (it was only deployed to learn):"))
			for _, r := range deploy.DeleteAll(cleanupCtx, k, t.policies) {
				fmt.Printf("  %s  %s: %s\n", applyFlag(r.OK, r.Skipped), r.Label, r.Msg)
			}
			fmt.Println(ui.Dim("  Policy file(s) kept in " + ac.OutDir + "/, review, then apply with enforcement."))
		}
	}
	active := func() []*target {
		var out []*target
		for _, t := range targets {
			if !t.done {
				out = append(out, t)
			}
		}
		return out
	}

	interrupted := false
	rnd := 0
	for len(active()) > 0 {
		rnd++
		if ctx.Err() != nil {
			interrupted = true
			break
		}

		fmt.Println(ui.Cyan(fmt.Sprintf("\n== Round %d ==", rnd)))

		// Generate and deploy every label's policies, then watch them all at
		// once.
		index := resolveIndex(ctx, k, cfg, fqdnIPs, ac.FqdnDump)
		anyBootstrap := false
		for _, t := range active() {
			heading(t)
			generateFor(t, index)
			paths, err := pipeline.WritePolicies(t.policies, ac.OutDir)
			if err != nil {
				return t.policies, err
			}
			sig := pipeline.Signature(t.policies)
			if rnd > 1 && sig == t.lastSig {
				fmt.Printf("  %d policy file(s)%s %s\n", len(paths), ui.Dim(" -> "+ac.OutDir+"/"), ui.Dim("(unchanged)"))
			} else {
				fmt.Printf("  %d policy file(s)%s\n", len(paths), ui.Dim(" -> "+ac.OutDir+"/"))
				pipeline.PrintNewNotes(t.policies, t.seenNotes)
			}
			t.lastSig = sig

			t.bootstrapping = len(paths) == 0
			if t.bootstrapping {
				// No app policy yet. Without one, policy_match_type==4 can
				// never fire; also, without a DNS rule Cilium's FQDN cache
				// never learns names this round. Deploy a standalone bootstrap
				// DNS policy, then watch all traffic and feed it back.
				if rnd == 1 {
					fmt.Println(ui.Yellow("  Nothing generated: no policy to check yet."))
					fmt.Println(ui.Dim("  Fix: confirm the label matches running pods."))
				}
				if ac.DryRun {
					fmt.Println(ui.Dim("  Skipping watch (--dry-run)."))
					finish(t)
					continue
				}
				fmt.Println("  Deploying temporary DNS visibility (no app policy yet):")
				t.bootstrapDNSAttempted = true
				deployBootstrapDNS(ctx, k, ac.Namespace, t.label)
				anyBootstrap = true
				if !multi {
					fmt.Printf("  Watching all traffic for %s (no policy yet)...\n", ac.Duration)
				}
				continue
			}

			if t.bootstrapDNSAttempted {
				fmt.Println(ui.Dim("  Removing temporary DNS visibility (app policy now covers it):"))
				removeBootstrapDNS(ctx, k, ac.Namespace, t.label)
				t.bootstrapDNSAttempted = false
			}

			if ac.DryRun {
				fmt.Println(ui.Dim("  Skipping deploy/verify (--dry-run)."))
				finish(t)
				continue
			}

			results := deploy.ApplyAll(ctx, k, t.policies, t.label, false)
			allOK := true
			for _, r := range results {
				if !r.OK {
					allOK = false
				}
			}
			if allOK && sig == t.lastApply {
				fmt.Println(ui.Dim("  Applying (safe mode): unchanged, re-applied."))
			} else {
				fmt.Println("  Applying (safe mode, can't block existing traffic):")
				for _, r := range results {
					fmt.Printf("    %s  %s: %s\n", applyFlag(r.OK, r.Skipped), r.Label, r.Msg)
				}
			}
			t.lastApply = sig
			if !multi {
				fmt.Printf("  Watching %s for anything still missing...\n", ac.Duration)
			}
		}
		if len(active()) == 0 {
			break // dry-run
		}

		// Once every label has a real policy, allFlowsWindow's bootstrap job
		// is done for good (see needsAllFlows's comment above).
		needsAllFlows.Store(anyBootstrap)

		if multi {
			fmt.Printf("  Watching %s...\n", ac.Duration)
		}
		verr := verify.Wait(ctx, ac.Duration, allFlowsWindow, dropFlowsWindow)
		stopped := errors.Is(verr, context.Canceled)
		var allFlows, dropFlows []*hubble.Flow
		if anyBootstrap {
			allFlows = allFlowsWindow.Snapshot()
		}
		if !stopped {
			dropFlows = dropFlowsWindow.Snapshot()
		}

		var recheckIndex *model.ResolveIndex
		var settledNow []*target // finished after the round, so its output isn't split up
		for _, t := range active() {
			if t.bootstrapping {
				heading(t)
				seen := forLabel(allFlows, t.label)
				if len(seen) == 0 {
					fmt.Println(ui.Yellow("  Warning: saw 0 flow(s) this round. If that's unexpected, " +
						"check the label matches running pods and that they're generating traffic."))
				} else {
					fmt.Printf("  Saw %d flow(s).\n", len(seen))
				}
				collect.MergeConnections(t.graph, seen, t.label, ac.Namespace)
				resolve.MergeFqdnFromFlows(fqdnIPs, seen)
				continue
			}

			// If the user interrupted mid-window, stop now rather than doing
			// a final resolve/apply on a cancelled context (which would fail
			// noisily); the deployed policy is torn down when finishing
			// either way.
			if stopped {
				continue
			}

			heading(t)
			drops := forLabel(dropFlows, t.label)
			counter := verify.SummarizeDrops(drops)
			verify.PrintDropSummary(counter)

			if len(counter) > 0 {
				// New blocked traffic: reset the stable streak and feed it
				// back so the next round generates the missing rules.
				t.stableStreak = 0
				fmt.Println(ui.Yellow("  Missing traffic added, continuing."))
				collect.MergeConnections(t.graph, drops, t.label, ac.Namespace)
				resolve.MergeFqdnFromFlows(fqdnIPs, drops)
				continue
			}

			t.stableStreak++
			fmt.Println(ui.Green("  Nothing missing."))
			// The DNS-visibility rule just spent `duration` letting the FQDN
			// cache populate. Re-resolve and redeploy once more so a round
			// that stabilizes early still ends up with toFQDNs instead of raw
			// IPs.
			if recheckIndex == nil {
				recheckIndex = resolveIndex(ctx, k, cfg, fqdnIPs, ac.FqdnDump)
			}
			generateFor(t, recheckIndex)
			if _, err := pipeline.WritePolicies(t.policies, ac.OutDir); err != nil {
				return t.policies, err
			}
			recheckSig := pipeline.Signature(t.policies)
			recheckResults := deploy.ApplyAll(ctx, k, t.policies, t.label, false)
			recheckOK := true
			for _, r := range recheckResults {
				if !r.OK {
					recheckOK = false
				}
			}
			if recheckOK && recheckSig == t.lastApply {
				fmt.Println(ui.Dim("  Re-checking for newly-resolved domain names: unchanged."))
			} else {
				fmt.Println(ui.Dim("  Re-checking for newly-resolved domain names:"))
				for _, r := range recheckResults {
					fmt.Printf("    %s  %s: %s\n", applyFlag(r.OK, r.Skipped), r.Label, r.Msg)
				}
				if recheckSig != t.lastSig {
					pipeline.PrintNewNotes(t.policies, t.seenNotes)
				}
			}
			t.lastSig = recheckSig
			t.lastApply = recheckSig

			if autoStop && t.stableStreak >= ac.Settle {
				fmt.Println(ui.Green(fmt.Sprintf("  Settled: %d stable round(s) in a row, nothing would be dropped.", ac.Settle)))
				settledNow = append(settledNow, t)
				continue
			}
			if autoStop {
				fmt.Println(ui.Green(fmt.Sprintf("  Stable (%d/%d).", t.stableStreak, ac.Settle)) +
					ui.Dim(" Still watching, Ctrl+C to stop."))
			} else {
				fmt.Println(ui.Green("  Stable for now.") + ui.Dim(" Still watching, Ctrl+C to stop."))
			}
		}
		for _, t := range settledNow {
			finish(t)
		}
		if stopped {
			interrupted = true
			break
		}
	}

	if interrupted {
		fmt.Println(ui.Dim("\nStopped (Ctrl+C). Finalizing..."))
	}

	// Tear down the persistent flow watch before finalizing (stopFollow is
	// also deferred, but no flow should land in the windows once
	// finalizing starts).
	stopFollow()
	follower.Wait()

	var policies []*generate.Policy
	for _, t := range targets {
		if !t.done {
			finish(t)
		}
		policies = append(policies, t.policies...)
	}
	return policies, nil
}

func deployBootstrapDNS(ctx context.Context, k *kube.Client, namespace, label string) {
	p := generate.BootstrapDNSPolicy(namespace, label)
	r := deploy.ApplyOne(ctx, k, p, label, "bootstrap-dns", false)
	fmt.Printf("    %s  bootstrap-dns: %s\n", applyFlag(r.OK, r.Skipped), r.Msg)
}

func removeBootstrapDNS(ctx context.Context, k *kube.Client, namespace, label string) {
	r := deploy.DeleteOne(ctx, k, generate.BootstrapDNSPolicyName(label), namespace, "bootstrap-dns")
	fmt.Printf("    %s  bootstrap-dns: %s\n", applyFlag(r.OK, r.Skipped), r.Msg)
}

func finalize(policies []*generate.Policy, outdir string) {
	var pruned []string
	for _, p := range policies {
		ns := p.ObservedNS
		if ns == "" {
			ns = p.Namespace
		}
		before := len(p.Notes)
		if p.PruneTempDNS() {
			for _, note := range p.Notes[before:] {
				pruned = append(pruned, fmt.Sprintf("[%s/%s] %s", ns, p.Name, note))
			}
		}
	}
	if _, err := pipeline.WritePolicies(policies, outdir); err != nil {
		ui.Warn("writing final policies: %v", err)
	}

	if len(pruned) > 0 {
		fmt.Println("  Cleanup:")
		for _, line := range pruned {
			fmt.Println(ui.Dim("  " + line))
		}
	}

	fmt.Println(ui.Cyan("\n-- Summary --"))
	suggestions := pipeline.CollectSuggestions(policies)
	if len(suggestions) > 0 {
		fmt.Println("Could combine into a wildcard:")
		for _, s := range suggestions {
			state := "not applied"
			if s.Forced {
				state = "forced"
			} else if s.Accepted {
				state = "accepted"
			}
			fmt.Printf("  *.%s  [%s]  %s\n", s.Suffix, state, ui.Dim(joinComma(s.Members)))
		}
	}
	unresolved := pipeline.CollectUnresolved(policies)
	if len(unresolved) > 0 {
		fmt.Println("Unmatched external IPs:")
		for _, u := range unresolved {
			fmt.Printf("  %s  port=%d/%s\n", u.CIDR, u.Port, u.Proto)
		}
	}
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

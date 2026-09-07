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
	"time"

	"github.com/kwistof/cnpgen/internal/deploy"
	"github.com/kwistof/cnpgen/internal/generate"
	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/pipeline"
	"github.com/kwistof/cnpgen/internal/resolve"
	"github.com/kwistof/cnpgen/internal/settings"
	"github.com/kwistof/cnpgen/internal/ui"
	"github.com/kwistof/cnpgen/internal/verify"
)

// Config holds the audit run parameters.
type Config struct {
	Label     string
	Namespace string
	OutDir    string
	Settle    int // stop after this many stable rounds in a row; 0 = never auto-stop
	Duration  time.Duration
	Accept    bool
	DryRun    bool
	FqdnDump  string
	Seed      *generate.Seed // from --seed-policy; merged into every round as a floor
}

func resolveIndex(ctx context.Context, k *kube.Client, cfg settings.Settings, flows []*hubble.Flow, fqdnDump string) *model.ResolveIndex {
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
	sources = append(sources, resolve.Source{Name: "flow-l7", Map: resolve.FqdnFromFlows(flows)})
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

// Run executes the audit loop. Returns the final policies and whether it
// stopped in a settled (nothing-missing) state.
//
// The loop always runs until stopped: either the user interrupts it (Ctrl+C),
// or, when ac.Settle > 0, it auto-stops once that many rounds in a row see no
// new blocked traffic. Either way, the deployed (non-enforcing) policy is
// removed from the cluster at the end; the generated policy file is kept.
func Run(ctx context.Context, k *kube.Client, cfg settings.Settings, ac Config, initialFlows []*hubble.Flow) ([]*generate.Policy, bool, error) {
	autoStop := ac.Settle > 0
	fmt.Println(ui.Bold(fmt.Sprintf("Auditing %s.", pipeline.DescribeTarget(ac.Label, ac.Namespace))))
	if autoStop {
		fmt.Println(ui.Dim(fmt.Sprintf("  Generate -> deploy (safe mode) -> watch %s -> repeat. "+
			"Stops after %d stable round(s) in a row, or Ctrl+C.", ac.Duration, ac.Settle)))
	} else {
		fmt.Println(ui.Dim(fmt.Sprintf("  Generate -> deploy (safe mode) -> watch %s -> repeat, until Ctrl+C.", ac.Duration)))
	}

	if n, err := k.CountPodsMatching(ctx, ac.Label, ac.Namespace); err != nil {
		ui.Warn("checking for matching pods: %v", err)
	} else if n == 0 {
		fmt.Println(ui.Yellow(fmt.Sprintf(
			"  Warning: no pods matching %s right now. Watching anyway in case they appear later; "+
				"if that's not expected, check the label and namespace.", pipeline.DescribeTarget(ac.Label, ac.Namespace))))
	} else {
		fmt.Println(ui.Dim(fmt.Sprintf("  %d pod(s) matching %s.", n, pipeline.DescribeTarget(ac.Label, ac.Namespace))))
	}

	flows := append([]*hubble.Flow(nil), initialFlows...)
	var policies []*generate.Policy
	settled := false // stopped in a nothing-missing state
	// bootstrapDNSAttempted tracks whether a deploy of the standalone DNS
	// policy was ever attempted this run, not whether it's known to have
	// succeeded: a Ctrl+C can make an apply look like it failed client-side
	// ("context canceled") while the write still lands server-side, so treat
	// "attempted" as the safe signal for cleanup and let the delete be a
	// no-op when there's nothing there.
	bootstrapDNSAttempted := false
	lastSig := ""   // previous round's pipeline.Signature(policies), for dedup
	lastApply := "" // signature at the time policies were last actually applied
	seenNotes := map[string]struct{}{}

	stableStreak := 0 // consecutive rounds with no new blocked traffic
	interrupted := false
	rnd := 0
	for {
		rnd++
		if ctx.Err() != nil {
			interrupted = true
			break
		}

		fmt.Println(ui.Cyan(fmt.Sprintf("\n== Round %d ==", rnd)))

		index := resolveIndex(ctx, k, cfg, flows, ac.FqdnDump)
		policies = pipeline.GeneratePolicies(flows, ac.Label, ac.Namespace, index, cfg, ac.Accept, true, false, ac.Seed)
		paths, err := pipeline.WritePolicies(policies, ac.OutDir)
		if err != nil {
			return policies, false, err
		}
		sig := pipeline.Signature(policies)
		if rnd > 1 && sig == lastSig {
			fmt.Printf("  %d policy file(s)%s %s\n", len(paths), ui.Dim(" -> "+ac.OutDir+"/"), ui.Dim("(unchanged)"))
		} else {
			fmt.Printf("  %d policy file(s)%s\n", len(paths), ui.Dim(" -> "+ac.OutDir+"/"))
			pipeline.PrintNewNotes(policies, seenNotes)
		}
		lastSig = sig

		if len(paths) == 0 {
			// No app policy yet. Without one, policy_match_type==4 can never
			// fire; also, without a DNS rule Cilium's FQDN cache never learns
			// names this round. Deploy a standalone bootstrap DNS policy, then
			// watch all traffic and feed it back.
			if rnd == 1 {
				fmt.Println(ui.Yellow("  Nothing generated: no policy to check yet."))
				fmt.Println(ui.Dim("  Fix: confirm the label matches running pods."))
			}
			if ac.DryRun {
				fmt.Println(ui.Dim("  Skipping watch (--dry-run)."))
				settled = true
				break
			}
			fmt.Println("  Deploying temporary DNS visibility (no app policy yet):")
			bootstrapDNSAttempted = true
			deployBootstrapDNS(ctx, k, ac.Namespace, ac.Label)
			fmt.Printf("  Watching all traffic for %s (no policy yet)...\n", ac.Duration)
			seen, verr := verify.VerifyWindow(ctx, k, ac.Label, ac.Duration, "")
			if len(seen) == 0 {
				fmt.Println(ui.Yellow("  Warning: saw 0 flow(s) this round. If that's unexpected, " +
					"check the label matches running pods and that they're generating traffic."))
			} else {
				fmt.Printf("  Saw %d flow(s).\n", len(seen))
			}
			flows = append(flows, seen...)
			if errors.Is(verr, context.Canceled) {
				interrupted = true
				break
			}
			continue
		}

		if bootstrapDNSAttempted {
			fmt.Println(ui.Dim("  Removing temporary DNS visibility (app policy now covers it):"))
			removeBootstrapDNS(ctx, k, ac.Namespace)
			bootstrapDNSAttempted = false
		}

		if ac.DryRun {
			fmt.Println(ui.Dim("  Skipping deploy/verify (--dry-run)."))
			settled = true
			break
		}

		results := deploy.ApplyAll(ctx, k, policies, false)
		allOK := true
		for _, r := range results {
			if !r.OK {
				allOK = false
			}
		}
		if allOK && sig == lastApply {
			fmt.Println(ui.Dim("  Applying (safe mode): unchanged, re-applied."))
		} else {
			fmt.Println("  Applying (safe mode, can't block existing traffic):")
			for _, r := range results {
				fmt.Printf("    %s  %s: %s\n", applyFlag(r.OK, r.Skipped), r.Label, r.Msg)
			}
		}
		lastApply = sig

		fmt.Printf("  Watching %s for anything still missing...\n", ac.Duration)
		dropFlows, verr := verify.VerifyWindow(ctx, k, ac.Label, ac.Duration, verify.DropCEL)

		// If the user interrupted mid-window, stop now rather than doing a
		// final resolve/apply on a cancelled context (which would fail noisily);
		// the deployed policy is torn down in finalize either way.
		if errors.Is(verr, context.Canceled) {
			interrupted = true
			break
		}

		counter := verify.SummarizeDrops(dropFlows)
		verify.PrintDropSummary(counter)

		if len(counter) == 0 {
			stableStreak++
			fmt.Println(ui.Green("  Nothing missing."))
			// The DNS-visibility rule just spent `duration` letting the FQDN
			// cache populate. Re-resolve and redeploy once more so a round that
			// stabilizes early still ends up with toFQDNs instead of raw IPs.
			index = resolveIndex(ctx, k, cfg, flows, ac.FqdnDump)
			policies = pipeline.GeneratePolicies(flows, ac.Label, ac.Namespace, index, cfg, ac.Accept, true, false, ac.Seed)
			if _, err := pipeline.WritePolicies(policies, ac.OutDir); err != nil {
				return policies, false, err
			}
			recheckSig := pipeline.Signature(policies)
			recheckResults := deploy.ApplyAll(ctx, k, policies, false)
			recheckOK := true
			for _, r := range recheckResults {
				if !r.OK {
					recheckOK = false
				}
			}
			if recheckOK && recheckSig == lastApply {
				fmt.Println(ui.Dim("  Re-checking for newly-resolved domain names: unchanged."))
			} else {
				fmt.Println(ui.Dim("  Re-checking for newly-resolved domain names:"))
				for _, r := range recheckResults {
					fmt.Printf("    %s  %s: %s\n", applyFlag(r.OK, r.Skipped), r.Label, r.Msg)
				}
				if recheckSig != sig {
					pipeline.PrintNewNotes(policies, seenNotes)
				}
			}
			lastSig = recheckSig
			lastApply = recheckSig

			if autoStop && stableStreak >= ac.Settle {
				fmt.Println(ui.Green(fmt.Sprintf("  Settled: %d stable round(s) in a row, nothing would be dropped.", ac.Settle)))
				settled = true
				break
			}
			if autoStop {
				fmt.Println(ui.Green(fmt.Sprintf("  Stable (%d/%d).", stableStreak, ac.Settle)) +
					ui.Dim(" Still watching, Ctrl+C to stop."))
			} else {
				fmt.Println(ui.Green("  Stable for now.") + ui.Dim(" Still watching, Ctrl+C to stop."))
			}
			continue
		}

		// New blocked traffic: reset the stable streak and feed it back so the
		// next round generates the missing rules.
		stableStreak = 0
		fmt.Println(ui.Yellow("  Missing traffic added, continuing."))
		flows = append(flows, dropFlows...)
	}

	if interrupted {
		fmt.Println(ui.Dim("\nStopped (Ctrl+C). Finalizing..."))
		settled = true
	}

	finalize(policies, ac.OutDir)

	// finalize uses a fresh (non-cancelled) context for cleanup so Ctrl+C
	// doesn't abort the teardown.
	cleanupCtx := context.Background()

	if bootstrapDNSAttempted {
		fmt.Println(ui.Dim("\nRemoving temporary DNS visibility (no app policy took over):"))
		removeBootstrapDNS(cleanupCtx, k, ac.Namespace)
	}

	// Always tidy up the non-enforcing policy we deployed while learning; the
	// generated file is what you keep and apply (with enforcement) yourself.
	// Nothing was deployed under --dry-run, so there's nothing to remove.
	if !ac.DryRun {
		fmt.Println(ui.Cyan("\nRemoving the policy from the cluster (it was only deployed to learn):"))
		for _, r := range deploy.DeleteAll(cleanupCtx, k, policies) {
			fmt.Printf("  %s  %s: %s\n", applyFlag(r.OK, r.Skipped), r.Label, r.Msg)
		}
		fmt.Println(ui.Dim("  Policy file(s) kept in " + ac.OutDir + "/, review, then apply with enforcement."))
	}

	return policies, settled, nil
}

func deployBootstrapDNS(ctx context.Context, k *kube.Client, namespace, label string) {
	p := generate.BootstrapDNSPolicy(namespace, label)
	r := deploy.ApplyOne(ctx, k, p, "bootstrap-dns", false)
	fmt.Printf("    %s  bootstrap-dns: %s\n", applyFlag(r.OK, r.Skipped), r.Msg)
}

func removeBootstrapDNS(ctx context.Context, k *kube.Client, namespace string) {
	r := deploy.DeleteOne(ctx, k, generate.BootstrapDNSPolicyName, namespace, "bootstrap-dns")
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

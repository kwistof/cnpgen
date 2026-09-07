// Package deploy applies and deletes generated policies on the cluster,
// honoring an ownership check.
//
// Every policy cnpgen generates carries the app.kubernetes.io/managed-by=cnpgen
// label. cnpgen only ever creates or updates a CiliumNetworkPolicy of a given
// name/namespace if it already carries that label (or doesn't exist yet): if
// a policy of the same name/namespace exists WITHOUT it, that's something
// else's (hand-written, another tool, or pre-existing) and cnpgen leaves it
// alone rather than overwriting or deleting it. The ownership check and the
// write happen as a single atomic operation against the cluster (see
// kube.ApplyManaged / kube.DeleteManaged) so there's no gap between "check
// the label" and "act" for something else to race into.
//
// Policies carry enableDefaultDeny:false, so applying them is additive: Cilium
// only starts counting what the policy would allow and cannot drop existing
// traffic. Safe to apply and re-apply during the audit loop.
package deploy

import (
	"context"
	"fmt"

	"github.com/kwistof/cnpgen/internal/generate"
	"github.com/kwistof/cnpgen/internal/kube"
)

// Result is the outcome of applying or deleting one policy.
type Result struct {
	Label   string
	OK      bool
	Msg     string
	Skipped bool
}

// ApplyOne applies a single policy, only ever creating or updating a policy
// cnpgen itself owns. If dryRun, the apply is skipped and it reports success.
func ApplyOne(ctx context.Context, k *kube.Client, p *generate.Policy, label string, dryRun bool) Result {
	if dryRun {
		return Result{Label: label, OK: true, Msg: "dry-run"}
	}
	own, err := k.ApplyManaged(ctx, p.Object(), generate.ManagedByLabel, generate.ManagedByValue)
	if err != nil {
		return Result{Label: label, OK: false, Msg: err.Error()}
	}
	if own == kube.OwnershipForeign {
		return Result{Label: label, OK: true, Skipped: true, Msg: fmt.Sprintf(
			"skipped: a CiliumNetworkPolicy named %q already exists in %q and wasn't "+
				"created by cnpgen (no %s=%s label), leaving it alone",
			p.Name, p.Namespace, generate.ManagedByLabel, generate.ManagedByValue)}
	}
	return Result{Label: label, OK: true, Msg: "applied"}
}

// DeleteOne deletes a single policy, only ever deleting a policy cnpgen
// itself owns.
func DeleteOne(ctx context.Context, k *kube.Client, name, namespace, label string) Result {
	own, err := k.DeleteManaged(ctx, name, namespace, generate.ManagedByLabel, generate.ManagedByValue)
	if err != nil {
		return Result{Label: label, OK: false, Msg: err.Error()}
	}
	switch own {
	case kube.OwnershipMissing:
		// Nothing to delete, so say so plainly rather than reporting a silent
		// success (e.g. its apply had failed earlier this run).
		return Result{Label: label, OK: true, Skipped: true,
			Msg: "nothing to delete: was never created on the cluster"}
	case kube.OwnershipForeign:
		return Result{Label: label, OK: true, Skipped: true, Msg: fmt.Sprintf(
			"skipped: %q in %q isn't cnpgen-managed, leaving it alone", name, namespace)}
	}
	return Result{Label: label, OK: true, Msg: "deleted"}
}

// ApplyAll applies every policy, in order. Returns the results.
func ApplyAll(ctx context.Context, k *kube.Client, policies []*generate.Policy, dryRun bool) []Result {
	results := make([]Result, 0, len(policies))
	for _, p := range policies {
		results = append(results, ApplyOne(ctx, k, p, p.FileName(), dryRun))
	}
	return results
}

// DeleteAll deletes every policy, in order. Returns the results.
func DeleteAll(ctx context.Context, k *kube.Client, policies []*generate.Policy) []Result {
	results := make([]Result, 0, len(policies))
	for _, p := range policies {
		results = append(results, DeleteOne(ctx, k, p.Name, p.Namespace, p.FileName()))
	}
	return results
}

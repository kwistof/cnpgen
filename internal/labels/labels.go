// Package labels canonicalizes Cilium endpoint labels: the single source of
// truth for turning a raw label list into an "app" identifier, a namespace,
// and the selectors / names derived from it.
package labels

import (
	"sort"
	"strings"
)

// appLabelKeys are the label keys, in priority order, that identify the "app"
// of an endpoint. The service account comes last: Cilium sets it on every pod,
// so it names pods carrying none of the usual app labels (e.g. only
// "control-plane=..."), which would otherwise have no identity at all.
var appLabelKeys = []string{
	"k8s:app.kubernetes.io/name",
	"k8s:app",
	"k8s:k8s-app",
	"k8s:rsName",
	serviceAccountKey,
}

// serviceAccountKey is the label Cilium derives from a pod's service account.
// The "default" service account is ignored: it is shared by every pod of a
// namespace that doesn't set one, so it identifies nothing.
const serviceAccountKey = "k8s:io.cilium.k8s.policy.serviceaccount"

// GetApp returns a canonical app identifier from a list of Cilium endpoint
// labels, e.g. "k8s:app.kubernetes.io/name=hybris-back" for normal pods, or
// "reserved:world" / "reserved:host" for reserved identities. Returns "" when
// no recognized label is present.
func GetApp(lbls []string) string {
	for _, l := range lbls {
		// Reserved identities look like "reserved:world" (no '=').
		if key, val, ok := strings.Cut(l, ":"); ok && key == "reserved" && !strings.Contains(l, "=") {
			return key + ":" + val
		}
	}
	for _, k := range appLabelKeys {
		for _, l := range lbls {
			key, val, ok := strings.Cut(l, "=")
			if !ok || key != k || val == "" {
				continue
			}
			if k == serviceAccountKey && val == "default" {
				continue
			}
			return key + "=" + val
		}
	}
	return ""
}

// HasLabel reports whether lbls contains the exact "key=value" pair given by
// filter (e.g. "app.kubernetes.io/name=foo"), with or without Cilium's "k8s:"
// prefix.
func HasLabel(lbls []string, filter string) bool {
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

// GetNamespace returns the pod namespace from a list of Cilium endpoint
// labels, or "". Hubble flow endpoints normally carry a top-level "namespace"
// field, but it is sometimes absent even though the labels have it (as
// "k8s:io.kubernetes.pod.namespace=..."); callers should prefer the top-level
// field and fall back to this.
func GetNamespace(lbls []string) string {
	const prefix = "k8s:io.kubernetes.pod.namespace="
	for _, l := range lbls {
		if strings.HasPrefix(l, prefix) {
			return l[len(prefix):]
		}
	}
	return ""
}

// stripK8sPrefix removes the "k8s:" prefix from a label key for use in a
// Kubernetes/Cilium selector.
func stripK8sPrefix(key string) string {
	return strings.TrimPrefix(key, "k8s:")
}

// isReserved reports whether an app string is a Cilium reserved identity.
func isReserved(app string) bool {
	return strings.HasPrefix(app, "reserved:")
}

// AppToLabelSelector converts a canonical app string into a {key: value}
// matchLabels map. Returns nil for reserved identities (world/host/
// kube-apiserver), which must be expressed via toEntities/fromEntities.
func AppToLabelSelector(app string) map[string]string {
	if isReserved(app) {
		return nil
	}
	key, val, found := strings.Cut(app, "=")
	if !found {
		return nil
	}
	return map[string]string{stripK8sPrefix(key): val}
}

// AppToPolicyName derives a safe, stable policy/file name from an app
// identifier.
func AppToPolicyName(app string) string {
	if key := strings.SplitN(app, "=", 2); len(key) == 2 {
		return key[1]
	}
	r := strings.NewReplacer(":", "-", "/", "-")
	return r.Replace(app)
}

// generatedKeys are pod labels Kubernetes sets itself, per controller
// revision or per pod: selecting on them would match one rollout or one pod,
// not the workload.
var generatedKeys = map[string]bool{
	"pod-template-hash":                        true,
	"controller-revision-hash":                 true,
	"pod-template-generation":                  true,
	"controller-uid":                           true,
	"job-name":                                 true,
	"statefulset.kubernetes.io/pod-name":       true,
	"apps.kubernetes.io/pod-index":             true,
	"batch.kubernetes.io/controller-uid":       true,
	"batch.kubernetes.io/job-name":             true,
	"batch.kubernetes.io/job-completion-index": true,
}

// FallbackSelector picks a selector label for a pod GetApp finds no app
// label on, in the same "k8s:key=value" form: the first (sorted) of the
// pod's own labels, skipping those Kubernetes or Cilium generate, or failing
// that its namespace label, so the selector is never narrower than the pod.
// Returns "" when ns is "".
func FallbackSelector(lbls []string, ns string) string {
	var own []string
	for _, l := range lbls {
		key, val, ok := strings.Cut(l, "=")
		if !ok || val == "" || !strings.HasPrefix(key, "k8s:") {
			continue
		}
		k := stripK8sPrefix(key)
		if strings.HasPrefix(k, "io.kubernetes.") || strings.HasPrefix(k, "io.cilium.") || generatedKeys[k] {
			continue
		}
		own = append(own, l)
	}
	if len(own) > 0 {
		sort.Strings(own)
		return own[0]
	}
	if ns == "" {
		return ""
	}
	return "k8s:io.kubernetes.pod.namespace=" + ns
}

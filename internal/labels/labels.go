// Package labels canonicalizes Cilium endpoint labels: the single source of
// truth for turning a raw label list into an "app" identifier, a namespace,
// and the selectors / names derived from it.
package labels

import "strings"

// appLabelKeys are the label keys, in priority order, that identify the "app"
// of an endpoint.
var appLabelKeys = []string{
	"k8s:app.kubernetes.io/name",
	"k8s:app",
	"k8s:k8s-app",
	"k8s:rsName",
}

// GetApp returns a canonical app identifier from a list of Cilium endpoint
// labels, e.g. "k8s:app.kubernetes.io/name=hybris-back" for normal pods, or
// "reserved:world" / "reserved:host" for reserved identities. Returns "" when
// no recognized label is present.
func GetApp(lbls []string) string {
	for _, l := range lbls {
		if !strings.Contains(l, "=") {
			// Reserved identities look like "reserved:world" (no '=').
			if !strings.Contains(l, ":") {
				continue
			}
			key, val, _ := strings.Cut(l, ":")
			if key == "reserved" {
				return key + ":" + val
			}
			continue
		}
		key, val, _ := strings.Cut(l, "=")
		for _, k := range appLabelKeys {
			if key == k {
				return key + "=" + val
			}
		}
	}
	return ""
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

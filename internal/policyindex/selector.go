package policyindex

import (
	"fmt"
	"strings"

	"github.com/kwistof/cnpgen/internal/hubble"
)

// requirement is one term of a Cilium endpoint selector. Cilium label keys
// carry a source ("k8s:app"); a key without one, or with "any", matches the
// key from any source.
type requirement struct {
	src    string // "" for any source
	key    string
	op     string // In | NotIn | Exists | DoesNotExist
	values []string
}

// selector is a conjunction of requirements; empty selects everything.
type selector []requirement

// endpointLabels indexes a flow endpoint's labels by key: one entry per
// "source:key=value" label (reserved identities like "reserved:host" have an
// empty value).
type endpointLabels map[string][]srcValue

type srcValue struct{ src, value string }

func parseEndpoint(ep hubble.Endpoint) endpointLabels {
	el := endpointLabels{}
	hasNS := false
	for _, l := range ep.Labels {
		src, rest, ok := strings.Cut(l, ":")
		if !ok {
			src, rest = "", l
		}
		key, val, _ := strings.Cut(rest, "=")
		if src == "k8s" && key == "io.kubernetes.pod.namespace" {
			hasNS = true
		}
		el[key] = append(el[key], srcValue{src, val})
	}
	// Hubble normally lists the namespace label; fall back to the top-level
	// field so a CNP's implicit namespace requirement still matches.
	if !hasNS && ep.Namespace != "" {
		el["io.kubernetes.pod.namespace"] = append(el["io.kubernetes.pod.namespace"], srcValue{"k8s", ep.Namespace})
	}
	return el
}

// splitKey separates a selector key's source prefix. Label keys can't
// contain ':', so the first one always ends the source.
func splitKey(k string) (src, key string) {
	if s, rest, ok := strings.Cut(k, ":"); ok {
		if s == "any" {
			s = ""
		}
		return s, rest
	}
	return "", k
}

func parseSelector(m map[string]any) (selector, error) {
	var sel selector
	ml, _ := m["matchLabels"].(map[string]any)
	for k, v := range ml {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("matchLabels %q: not a string", k)
		}
		src, key := splitKey(k)
		sel = append(sel, requirement{src: src, key: key, op: "In", values: []string{s}})
	}
	me, _ := m["matchExpressions"].([]any)
	for _, e := range me {
		em, _ := e.(map[string]any)
		k, _ := em["key"].(string)
		op, _ := em["operator"].(string)
		switch op {
		case "In", "NotIn", "Exists", "DoesNotExist":
		default:
			return nil, fmt.Errorf("matchExpressions %q: unknown operator %q", k, op)
		}
		var vals []string
		raw, _ := em["values"].([]any)
		for _, v := range raw {
			if s, ok := v.(string); ok {
				vals = append(vals, s)
			}
		}
		src, key := splitKey(k)
		sel = append(sel, requirement{src: src, key: key, op: op, values: vals})
	}
	return sel, nil
}

func (s selector) matches(el endpointLabels) bool {
	for _, r := range s {
		if !r.matches(el) {
			return false
		}
	}
	return true
}

func (r requirement) matches(el endpointLabels) bool {
	var vals []string
	for _, sv := range el[r.key] {
		if r.src == "" || sv.src == r.src {
			vals = append(vals, sv.value)
		}
	}
	switch r.op {
	case "Exists":
		return len(vals) > 0
	case "DoesNotExist":
		return len(vals) == 0
	case "In":
		return anyIn(vals, r.values)
	case "NotIn":
		return !anyIn(vals, r.values)
	}
	return false
}

func anyIn(have, want []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}

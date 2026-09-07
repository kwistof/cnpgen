package generate

import (
	"sort"

	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/settings"
	"github.com/kwistof/cnpgen/internal/ui"
)

// appendBoilerplate adds rules every policy needs regardless of observed
// traffic: kube-apiserver egress, any --allow-extra destinations, and the
// kube-dns DNS-visibility rule (required for toFQDNs; temporary during audit).
// It records the DNS rule (whether injected whole or merged into an existing
// rule) on the Policy so prune can undo it later. Returns the updated rules.
func (p *Policy) appendBoilerplate(egressRules []any, cfg settings.Settings, hasFqdns, tempDNS bool) []any {
	// Every pod may reach the Kubernetes API server. Add the port to an
	// existing toEntities:[kube-apiserver] rule if one exists, else append.
	egressRules = addEntityPort(egressRules, "kube-apiserver", 443, "TCP")

	// Extra always-allowed egress destinations.
	for _, e := range cfg.ExtraEgress {
		if e.CIDR == "" {
			continue
		}
		rule := newOMap().set("toCIDR", []any{e.CIDR})
		if e.Port != 0 {
			if ports := buildPorts([]portProto{{Port: e.Port, Proto: e.Protocol}}); ports != nil {
				rule.set("toPorts", ports)
			}
		}
		if e.Comment != "" {
			p.cidrComments[e.CIDR] = e.Comment
		}
		egressRules = append(egressRules, rule)
	}

	if !hasFqdns && !tempDNS {
		return egressRules
	}

	// DNS visibility rule. If an existing rule already targets kube-dns:53/UDP
	// (from observed traffic), augment it in place; else inject a fresh rule.
	if existing := findKubeDNS53Rule(egressRules); existing != nil {
		if tp, ok := existing.get("toPorts"); ok {
			for _, item := range tp.([]any) {
				om := item.(*omap)
				if ports, ok := om.get("ports"); ok {
					for _, pitem := range ports.([]any) {
						pom := pitem.(*omap)
						port, _ := pom.get("port")
						proto, _ := pom.get("protocol")
						if port == "53" && proto == "UDP" {
							om.set("rules", newOMap().set("dns", []any{newOMap().set("matchPattern", "*")}))
						}
					}
				}
			}
		}
		p.dnsMergedRule = existing
	} else {
		dnsRule := newOMap().
			set("toEndpoints", []any{newOMap().set("matchLabels", newOMap().
				set("k8s-app", "kube-dns").
				set("io.kubernetes.pod.namespace", "kube-system"))}).
			set("toPorts", []any{newOMap().
				set("ports", []any{newOMap().set("port", "53").set("protocol", "UDP")}).
				set("rules", newOMap().set("dns", []any{newOMap().set("matchPattern", "*")}))})
		egressRules = append(egressRules, dnsRule)
		p.dnsRule = dnsRule
	}

	if hasFqdns {
		p.Notes = append(p.Notes,
			"added DNS visibility (kube-dns:53), needed for toFQDNs, stays in the final policy.")
	} else {
		p.Notes = append(p.Notes,
			"added DNS visibility (kube-dns:53) temporarily, to learn IPs for external domains.\n    "+
				ui.Dim("Removed automatically if no toFQDNs rule ends up needing it."))
	}
	return egressRules
}

// addEntityPort adds `port` to an existing bare toEntities:[entity] rule, else
// appends a new rule for it.
func addEntityPort(egressRules []any, entity string, port int32, proto string) []any {
	for _, item := range egressRules {
		rule, ok := item.(*omap)
		if !ok {
			continue
		}
		ent, ok := rule.get("toEntities")
		if !ok {
			continue
		}
		if list, ok := ent.([]any); ok && len(list) == 1 && list[0] == entity {
			ports := buildPorts([]portProto{{Port: port, Proto: proto}})
			existingPorts, has := rule.get("toPorts")
			if has {
				ep := existingPorts.([]any)
				if len(ep) > 0 {
					first := ep[0].(*omap)
					fp, _ := first.get("ports")
					newPorts, _ := ports[0].(*omap).get("ports")
					existing := fp.([]any)
					for _, np := range newPorts.([]any) {
						if !containsPort(existing, np.(*omap)) {
							existing = append(existing, np)
						}
					}
					first.set("ports", existing)
				}
			} else {
				rule.set("toPorts", ports)
			}
			return egressRules
		}
	}
	rule := newOMap().set("toEntities", []any{entity})
	if ports := buildPorts([]portProto{{Port: port, Proto: proto}}); ports != nil {
		rule.set("toPorts", ports)
	}
	return append(egressRules, rule)
}

func containsPort(list []any, p *omap) bool {
	pp, _ := p.get("port")
	pproto, _ := p.get("protocol")
	for _, item := range list {
		om := item.(*omap)
		port, _ := om.get("port")
		proto, _ := om.get("protocol")
		if port == pp && proto == pproto {
			return true
		}
	}
	return false
}

// findKubeDNS53Rule returns an existing egress rule targeting kube-dns:53/UDP.
func findKubeDNS53Rule(egressRules []any) *omap {
	for _, item := range egressRules {
		rule, ok := item.(*omap)
		if !ok {
			continue
		}
		eps, ok := rule.get("toEndpoints")
		if !ok {
			continue
		}
		list, ok := eps.([]any)
		if !ok || len(list) != 1 {
			continue
		}
		ml, ok := list[0].(*omap).get("matchLabels")
		if !ok {
			continue
		}
		app, _ := ml.(*omap).get("k8s-app")
		if app != "kube-dns" {
			continue
		}
		tp, ok := rule.get("toPorts")
		if !ok {
			continue
		}
		for _, tpItem := range tp.([]any) {
			ports, ok := tpItem.(*omap).get("ports")
			if !ok {
				continue
			}
			for _, pItem := range ports.([]any) {
				pom := pItem.(*omap)
				port, _ := pom.get("port")
				proto, _ := pom.get("protocol")
				if port == "53" && proto == "UDP" {
					return rule
				}
			}
		}
	}
	return nil
}

// PruneTempDNS removes the temporary DNS-visibility addition from a policy that
// ended up with no toFQDNs. Returns true if anything was removed. Uses the
// recorded rule pointers to tell "injected whole rule -> drop it" apart from
// "merged into a real rule -> strip just the dns block".
func (p *Policy) PruneTempDNS() bool {
	if p.spec == nil {
		return false
	}
	egressVal, ok := p.spec.get("egress")
	if !ok {
		return false
	}
	egress := egressVal.([]any)

	for _, item := range egress {
		if rule, ok := item.(*omap); ok {
			if _, has := rule.get("toFQDNs"); has {
				return false // still has FQDNs, keep DNS visibility
			}
		}
	}

	var newEgress []any
	changed := false
	for _, item := range egress {
		rule := item.(*omap)
		if rule == p.dnsRule {
			changed = true
			continue // drop the injected-whole rule
		}
		if rule == p.dnsMergedRule {
			if stripDNSVisibility(rule) {
				changed = true
			}
		}
		newEgress = append(newEgress, rule)
	}
	if changed {
		p.spec.set("egress", newEgress)
		p.Notes = append(p.Notes, "removed temporary DNS visibility: not needed after all.")
	}
	return changed
}

// stripDNSVisibility removes an injected rules.dns block from a rule without
// dropping the rule.
func stripDNSVisibility(rule *omap) bool {
	tp, ok := rule.get("toPorts")
	if !ok {
		return false
	}
	changed := false
	for _, item := range tp.([]any) {
		om := item.(*omap)
		if rules, ok := om.get("rules"); ok {
			if _, hasDNS := rules.(*omap).get("dns"); hasDNS {
				// Remove the "rules" key entirely.
				delete(om.vals, "rules")
				for i, k := range om.keys {
					if k == "rules" {
						om.keys = append(om.keys[:i], om.keys[i+1:]...)
						break
					}
				}
				changed = true
			}
		}
	}
	return changed
}

// ---- small ordering / set helpers ----

func setToSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mapKeysSet(m map[string]string) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mapToOMap(m map[string]string) *omap {
	o := newOMap()
	for _, k := range sortedMapKeys(m) {
		o.set(k, m[k])
	}
	return o
}

func mergeSorted(a, b []string) []string {
	set := map[string]struct{}{}
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, x := range b {
		set[x] = struct{}{}
	}
	out := setToSlice(set)
	sort.Strings(out)
	return out
}

// sortedEndpoints returns the map's endpoint keys sorted by (App, Namespace),
// for deterministic policy output.
func sortedEndpoints(m map[model.Endpoint][]portProto) []model.Endpoint {
	out := make([]model.Endpoint, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		return out[i].Namespace < out[j].Namespace
	})
	return out
}

func sortedPortKeys(m map[portProto]map[string]string) []portProto {
	out := make([]portProto, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return lessPortProto(out[i], out[j]) })
	return out
}

// lessPortProto orders (port, proto) pairs by port then protocol, so toCIDR
// blocks come out in a deterministic order.
func lessPortProto(a, b portProto) bool {
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	return a.Proto < b.Proto
}

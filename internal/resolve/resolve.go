// Package resolve correlates external IPs to FQDNs.
//
// Sources, by confidence (a lower one never overwrites the source tag of a
// higher one):
//  1. FQDN cache: `cilium fqdn cache list -o json` per pod, or a saved dump
//  2. flow L7/names: when flows carry destination_names
//  3. known-IP overrides (--known-ip): authoritative, always win
package resolve

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/model"
	"github.com/kwistof/cnpgen/internal/ui"
)

// Source is a named fqdn->ips mapping, in priority order (highest first).
type Source struct {
	Name string
	Map  map[string]map[string]struct{}
}

func normFqdn(f string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f)), ".")
}

// FqdnCacheLive returns fqdn -> set(ips) aggregated across all Cilium pods, by
// running `cilium fqdn cache list -o json` in each.
func FqdnCacheLive(ctx context.Context, k *kube.Client) (map[string]map[string]struct{}, error) {
	pods, err := k.CiliumPods(ctx)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		ui.Warn("No cilium pods found.")
		return map[string]map[string]struct{}{}, nil
	}

	argv := []string{"cilium", "fqdn", "cache", "list", "-o", "json"}

	type cacheEntry struct {
		Fqdn string   `json:"fqdn"`
		IPs  []string `json:"ips"`
	}

	var mu sync.Mutex
	fqdnIPs := map[string]map[string]struct{}{}
	var wg sync.WaitGroup
	for _, pod := range pods {
		wg.Add(1)
		go func(pod kube.Pod) {
			defer wg.Done()
			out, _, err := k.Exec(ctx, pod.Name, argv)
			if err != nil {
				ui.Warn("%s (%s): %v", pod.Name, pod.Node, err)
				return
			}
			out = strings.TrimSpace(out)
			if out == "" {
				return
			}
			var entries []cacheEntry
			if err := json.Unmarshal([]byte(out), &entries); err != nil {
				ui.Warn("%s (%s): failed to parse fqdn cache JSON", pod.Name, pod.Node)
				return
			}
			mu.Lock()
			for _, e := range entries {
				fqdn := normFqdn(e.Fqdn)
				if fqdn == "" {
					continue
				}
				addIPs(fqdnIPs, fqdn, e.IPs)
			}
			mu.Unlock()
		}(pod)
	}
	wg.Wait()
	ui.Log("FQDN cache: %d unique FQDNs", len(fqdnIPs))
	return fqdnIPs, nil
}

var (
	dumpFqdnRe = regexp.MustCompile(`^\s{2}([A-Za-z0-9._-]+\.)\s*$`)
	dumpIPsRe  = regexp.MustCompile(`^\s+IPs\s+:\s*(.+)$`)
)

// FqdnCacheFromDump parses the AGGREGATE section of a saved *-fqdn dump into
// fqdn -> set(ips).
func FqdnCacheFromDump(path string) (map[string]map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fqdnIPs := map[string]map[string]struct{}{}
	inAggregate := false
	current := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.Contains(line, "AGGREGATE") {
			inAggregate = true
			continue
		}
		if !inAggregate {
			continue
		}
		if m := dumpFqdnRe.FindStringSubmatch(line); m != nil {
			current = normFqdn(m[1])
			if _, ok := fqdnIPs[current]; !ok {
				fqdnIPs[current] = map[string]struct{}{}
			}
			continue
		}
		if m := dumpIPsRe.FindStringSubmatch(line); m != nil && current != "" {
			for _, ip := range strings.Split(m[1], ",") {
				ip = strings.TrimSpace(ip)
				if ip != "" {
					fqdnIPs[current][ip] = struct{}{}
				}
			}
		}
	}
	ui.Log("FQDN dump %s: %d unique FQDNs", path, len(fqdnIPs))
	return fqdnIPs, nil
}

// FqdnFromFlows extracts fqdn -> set(ips) from flow destination_names, if any.
func FqdnFromFlows(flows []*hubble.Flow) map[string]map[string]struct{} {
	fqdnIPs := map[string]map[string]struct{}{}
	for _, flow := range flows {
		if flow == nil {
			continue
		}
		ip := flow.DstIP()
		if ip == "" {
			continue
		}
		for _, name := range flow.DestinationNames {
			n := normFqdn(name)
			if n == "" {
				continue
			}
			addIPs(fqdnIPs, n, []string{ip})
		}
	}
	return fqdnIPs
}

// BuildIndex merges fqdn->ips sources (highest confidence first) into a
// ResolveIndex, then applies authoritative ip overrides (which always win).
func BuildIndex(sources []Source, ipOverrides map[string]string) *model.ResolveIndex {
	index := model.NewResolveIndex()

	for _, src := range sources {
		for fqdn, ips := range src.Map {
			if index.FqdnToIPs[fqdn] == nil {
				index.FqdnToIPs[fqdn] = map[string]struct{}{}
			}
			for ip := range ips {
				index.FqdnToIPs[fqdn][ip] = struct{}{}
				rf := index.IPToFqdns[ip]
				if rf == nil {
					rf = &model.ResolvedFqdn{IP: ip, Fqdns: map[string]struct{}{}, Source: src.Name}
					index.IPToFqdns[ip] = rf
				}
				rf.Fqdns[fqdn] = struct{}{}
			}
		}
	}

	for ip, fqdn := range ipOverrides {
		rf := index.IPToFqdns[ip]
		if rf == nil {
			rf = &model.ResolvedFqdn{IP: ip, Fqdns: map[string]struct{}{}}
			index.IPToFqdns[ip] = rf
		}
		rf.Fqdns = map[string]struct{}{normFqdn(fqdn): {}}
		rf.Source = "config"
	}

	ui.Log("ResolveIndex: %d IPs, %d FQDNs", len(index.IPToFqdns), len(index.FqdnToIPs))
	return index
}

func addIPs(m map[string]map[string]struct{}, fqdn string, ips []string) {
	if m[fqdn] == nil {
		m[fqdn] = map[string]struct{}{}
	}
	for _, ip := range ips {
		if ip != "" {
			m[fqdn][ip] = struct{}{}
		}
	}
}

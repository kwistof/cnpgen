// Package patterns collapses FQDNs into matchName / matchPattern entries using
// a suggest-then-confirm rule.
//
// When several sibling FQDNs share a parent domain (e.g. tenant1.auth0.com,
// tenant2.auth0.com -> *.auth0.com) it can suggest collapsing them to one
// matchPattern; otherwise FQDNs stay as exact matchName entries. A wildcard is
// only ever emitted when it's in the allow-domain list (forced) or the
// operator confirmed suggestions via --accept-suggestions.
package patterns

import (
	"sort"
	"strings"
)

// wildcardThreshold is the minimum number of sibling FQDNs under one parent
// domain before a wildcard is even suggested.
const wildcardThreshold = 2

// denylistSuffixes are multi-label public suffixes we must never treat as a
// wildcardable parent (wildcarding these would allow "anything on this shared
// provider").
var denylistSuffixes = map[string]struct{}{
	"com": {}, "net": {}, "org": {}, "io": {}, "co.uk": {}, "com.au": {},
	"co.jp": {}, "co.nz": {},
	"core.windows.net": {}, "blob.core.windows.net": {}, "cache.windows.net": {},
	"database.azure.com": {}, "azure.com": {}, "azurefd.net": {}, "azure-api.net": {},
	"cloudflare.net": {}, "fastly.net": {}, "akamaitechnologies.com": {},
	"cluster.local": {}, "svc.cluster.local": {},
	"elastic-cloud.com": {}, "windows.net": {}, "appspot.com": {},
}

// Suggestion is a candidate wildcard collapse, reported to the user.
type Suggestion struct {
	Suffix   string   // e.g. "eu.auth0.com" -> pattern "*.suffix"
	Members  []string // FQDNs it would collapse (sorted)
	Forced   bool     // present in the allow-domain list
	Accepted bool     // operator-accepted (--accept-suggestions)
}

// Result is the outcome of collapsing a set of FQDNs.
type Result struct {
	MatchNames    []string     // exact FQDNs
	MatchPatterns []string     // "*.suffix" strings
	Suggestions   []Suggestion // for the report
}

func parentSuffix(fqdn string) string {
	l := strings.Split(fqdn, ".")
	if len(l) < 3 {
		return ""
	}
	return strings.Join(l[1:], ".")
}

func patternSuffix(pattern string) string {
	return strings.TrimPrefix(pattern, "*.")
}

func normFqdn(f string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f)), ".")
}

// Collapse turns a set of FQDNs into matchName / matchPattern entries.
//
// allowDomains are wildcard patterns (e.g. "*.auth0.com") always emitted when
// they cover an observed FQDN. pinDomains are FQDNs that must always stay an
// exact matchName, never absorbed into a wildcard.
func Collapse(fqdns []string, allowDomains, pinDomains []string, accept bool) Result {
	forceSuffixes := map[string]struct{}{}
	force := map[string]struct{}{}
	for _, p := range allowDomains {
		force[p] = struct{}{}
		forceSuffixes[patternSuffix(p)] = struct{}{}
	}
	pinned := map[string]struct{}{}
	for _, p := range pinDomains {
		pinned[normFqdn(p)] = struct{}{}
	}

	// Split incoming FQDNs into plain hosts and any explicit "*." patterns
	// (which pass straight through).
	hosts := map[string]struct{}{}
	explicitPatterns := map[string]struct{}{}
	for _, f := range fqdns {
		n := normFqdn(f)
		if n == "" {
			continue
		}
		if strings.HasPrefix(n, "*.") {
			explicitPatterns[n] = struct{}{}
		} else {
			hosts[n] = struct{}{}
		}
	}

	var result Result

	// Group by parent suffix. Pinned FQDNs never join a group.
	bySuffix := map[string]map[string]struct{}{}
	for f := range hosts {
		if _, pin := pinned[f]; pin {
			continue
		}
		suffix := parentSuffix(f)
		if suffix == "" {
			continue
		}
		if bySuffix[suffix] == nil {
			bySuffix[suffix] = map[string]struct{}{}
		}
		bySuffix[suffix][f] = struct{}{}
	}

	consumed := map[string]struct{}{}

	for _, suffix := range sortedKeys(bySuffix) {
		if _, deny := denylistSuffixes[suffix]; deny {
			continue
		}
		members := bySuffix[suffix]
		_, forced := forceSuffixes[suffix]
		eligible := len(members) >= wildcardThreshold
		if !forced && !eligible {
			continue
		}
		result.Suggestions = append(result.Suggestions, Suggestion{
			Suffix:   suffix,
			Members:  sortedSet(members),
			Forced:   forced,
			Accepted: accept,
		})
		if forced || accept {
			result.MatchPatterns = append(result.MatchPatterns, "*."+suffix)
			for m := range members {
				consumed[m] = struct{}{}
			}
		}
	}

	// Forced patterns that cover an observed FQDN but weren't emitted above
	// (e.g. a singleton host under *.adyen.com).
	var forcedSorted []string
	for p := range force {
		forcedSorted = append(forcedSorted, p)
	}
	sort.Strings(forcedSorted)
	for _, pattern := range forcedSorted {
		if contains(result.MatchPatterns, pattern) {
			continue
		}
		suffix := patternSuffix(pattern)
		covered := map[string]struct{}{}
		for f := range hosts {
			if _, pin := pinned[f]; pin {
				continue
			}
			if f == suffix || strings.HasSuffix(f, "."+suffix) {
				covered[f] = struct{}{}
			}
		}
		if len(covered) > 0 {
			result.MatchPatterns = append(result.MatchPatterns, pattern)
			for f := range covered {
				consumed[f] = struct{}{}
			}
		}
	}

	// Remaining hosts -> matchName (includes anything pinned).
	for _, f := range sortedSet(hosts) {
		if _, done := consumed[f]; done {
			continue
		}
		result.MatchNames = append(result.MatchNames, f)
	}

	// Explicit patterns passed through.
	for _, p := range sortedSet(explicitPatterns) {
		if !contains(result.MatchPatterns, p) {
			result.MatchPatterns = append(result.MatchPatterns, p)
		}
	}

	result.MatchNames = dedup(result.MatchNames)
	result.MatchPatterns = dedup(result.MatchPatterns)
	return result
}

func sortedKeys(m map[string]map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func dedup(seq []string) []string {
	seen := map[string]struct{}{}
	out := seq[:0:0]
	for _, x := range seq {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

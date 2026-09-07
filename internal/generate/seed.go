// Seeding a run from an existing CiliumNetworkPolicy file (--seed-policy):
// its toFQDNs/toCIDR egress rules become an unconditional floor merged into
// every round's output, regardless of whether traffic to them is actually
// observed this run. Real traffic still refines/extends the policy normally;
// nothing seeded is ever dropped.

package generate

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

// rawCNP is the subset of a CiliumNetworkPolicy's shape seed parsing reads.
type rawCNP struct {
	Spec struct {
		EndpointSelector struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"endpointSelector"`
		Egress []rawRule `json:"egress"`
	} `json:"spec"`
}

type rawRule struct {
	ToFQDNs []rawFQDNEntry `json:"toFQDNs"`
	ToCIDR  []string       `json:"toCIDR"`
	ToPorts []rawToPorts   `json:"toPorts"`
}

type rawFQDNEntry struct {
	MatchName    string `json:"matchName"`
	MatchPattern string `json:"matchPattern"`
}

type rawToPorts struct {
	Ports []rawPort `json:"ports"`
}

type rawPort struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

// Seed holds the egress rules pulled from an existing CNP, to merge into a
// freshly generated policy for the same app.
type Seed struct {
	// fqdnsByPort mirrors routeExternal's fqdnsByPort: per port/proto, the
	// set of FQDNs (plain hosts or "*."-prefixed patterns) already allowed.
	fqdnsByPort map[portProto]map[string]struct{}
	// cidrByPort mirrors routeExternal's cidrByPort: per port/proto, CIDR ->
	// comment (always "" for seeded entries; seeding never fabricates one).
	cidrByPort map[portProto]map[string]string
}

// LoadSeed parses an existing CiliumNetworkPolicy file and extracts its
// egress toFQDNs/toCIDR rules as a Seed. label is the -l value for this run
// ("key=value"); if the seed file's endpointSelector doesn't have that exact
// key/value, LoadSeed returns an error rather than silently merging in what
// may be a different app's rules.
func LoadSeed(path, label string) (*Seed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cnp rawCNP
	if err := yaml.Unmarshal(raw, &cnp); err != nil {
		return nil, fmt.Errorf("parsing %s as a CiliumNetworkPolicy: %w", path, err)
	}

	if key, val, ok := strings.Cut(label, "="); ok {
		if got, present := cnp.Spec.EndpointSelector.MatchLabels[key]; !present || got != val {
			return nil, fmt.Errorf(
				"endpointSelector.matchLabels in %s doesn't have %s=%s (found %v): "+
					"pass --seed-policy only for the file matching -l %s, or check the file",
				path, key, val, cnp.Spec.EndpointSelector.MatchLabels, label)
		}
	}

	s := &Seed{
		fqdnsByPort: map[portProto]map[string]struct{}{},
		cidrByPort:  map[portProto]map[string]string{},
	}
	for _, rule := range cnp.Spec.Egress {
		if len(rule.ToFQDNs) == 0 && len(rule.ToCIDR) == 0 {
			continue
		}
		keys := seedPortKeys(rule.ToPorts)
		for _, entry := range rule.ToFQDNs {
			name := entry.MatchName
			if name == "" {
				name = entry.MatchPattern
			}
			if name == "" {
				continue
			}
			for _, key := range keys {
				if s.fqdnsByPort[key] == nil {
					s.fqdnsByPort[key] = map[string]struct{}{}
				}
				s.fqdnsByPort[key][strings.ToLower(name)] = struct{}{}
			}
		}
		for _, cidr := range rule.ToCIDR {
			for _, key := range keys {
				if s.cidrByPort[key] == nil {
					s.cidrByPort[key] = map[string]string{}
				}
				if _, exists := s.cidrByPort[key][cidr]; !exists {
					s.cidrByPort[key][cidr] = ""
				}
			}
		}
	}
	return s, nil
}

// seedPortKeys returns one portProto per (port, protocol) pair in toPorts, or
// a single zero-value portProto (no port restriction) if toPorts is empty.
func seedPortKeys(toPorts []rawToPorts) []portProto {
	var keys []portProto
	for _, tp := range toPorts {
		for _, p := range tp.Ports {
			port, err := strconv.Atoi(p.Port)
			if err != nil {
				continue
			}
			proto := p.Protocol
			if proto == "" {
				proto = "TCP"
			}
			keys = append(keys, portProto{Port: int32(port), Proto: proto})
		}
	}
	if len(keys) == 0 {
		keys = []portProto{{}}
	}
	return keys
}

// mergeInto folds the seed's FQDNs/CIDRs into routeExternal's working maps,
// as an unconditional floor: every seeded entry is added regardless of
// whether it was also observed this round.
func (s *Seed) mergeInto(fqdnsByPort map[portProto]map[string]struct{}, cidrByPort map[portProto]map[string]string) {
	if s == nil {
		return
	}
	for key, fqdns := range s.fqdnsByPort {
		if fqdnsByPort[key] == nil {
			fqdnsByPort[key] = map[string]struct{}{}
		}
		for f := range fqdns {
			fqdnsByPort[key][f] = struct{}{}
		}
	}
	for key, cidrs := range s.cidrByPort {
		if cidrByPort[key] == nil {
			cidrByPort[key] = map[string]string{}
		}
		for c, comment := range cidrs {
			if _, exists := cidrByPort[key][c]; !exists {
				cidrByPort[key][c] = comment
			}
		}
	}
}

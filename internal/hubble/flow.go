// Package hubble models the subset of the Hubble flow JSON that cnpgen reads.
//
// `hubble observe --output json` emits one JSON object per line, each wrapping
// the real flow under a "flow" key. Fields not needed by cnpgen are omitted.
package hubble

import "encoding/json"

// Endpoint is a flow source or destination.
type Endpoint struct {
	Namespace string   `json:"namespace"`
	Labels    []string `json:"labels"`
}

// L4 carries the transport-layer port for TCP or UDP.
type L4 struct {
	TCP *struct {
		DestinationPort int32 `json:"destination_port"`
	} `json:"TCP"`
	UDP *struct {
		DestinationPort int32 `json:"destination_port"`
	} `json:"UDP"`
}

// IPBlock carries the L3 addresses.
type IPBlock struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// Flow is a single Hubble flow.
type Flow struct {
	Type             string   `json:"Type"`
	IsReply          bool     `json:"is_reply"`
	Source           Endpoint `json:"source"`
	Destination      Endpoint `json:"destination"`
	L4               L4       `json:"l4"`
	IP               IPBlock  `json:"IP"`
	DestinationNames []string `json:"destination_names"`
	PolicyMatchType  uint32   `json:"policy_match_type"`
}

// wrapper matches the `{"flow": {...}}` envelope Hubble emits per line.
type wrapper struct {
	Flow *Flow `json:"flow"`
}

// Port returns the destination port and protocol ("TCP"/"UDP"), or (0, "").
func (f *Flow) Port() (int32, string) {
	if f.L4.TCP != nil {
		return f.L4.TCP.DestinationPort, "TCP"
	}
	if f.L4.UDP != nil {
		return f.L4.UDP.DestinationPort, "UDP"
	}
	return 0, ""
}

// DstIP returns the destination IP from the flow's L3 block.
func (f *Flow) DstIP() string {
	return f.IP.Destination
}

// SrcIP returns the source IP from the flow's L3 block.
func (f *Flow) SrcIP() string {
	return f.IP.Source
}

// ParseLine parses one line of Hubble JSON output into a Flow. It accepts both
// the `{"flow": {...}}` envelope and a bare flow object. Returns nil (no error)
// for lines that carry no flow (e.g. Hubble's ring-buffer sentinels).
func ParseLine(line []byte) (*Flow, error) {
	var w wrapper
	if err := json.Unmarshal(line, &w); err == nil && w.Flow != nil {
		return w.Flow, nil
	}
	var f Flow
	if err := json.Unmarshal(line, &f); err != nil {
		return nil, err
	}
	// A bare object with no recognizable content (e.g. a sentinel) yields an
	// empty Flow; treat "no source and no destination" as "not a flow".
	if len(f.Source.Labels) == 0 && len(f.Destination.Labels) == 0 &&
		f.IP.Source == "" && f.IP.Destination == "" {
		return nil, nil
	}
	return &f, nil
}

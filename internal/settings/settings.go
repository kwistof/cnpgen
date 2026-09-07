// Package settings carries the handful of run-time tuning values the policy
// generator reads. There is no config file: every setting comes from a
// repeatable CLI flag on `generate` or `audit`.
package settings

import (
	"regexp"
	"strconv"
	"strings"
)

// ExtraEgress is one always-allowed destination (--allow-extra).
type ExtraEgress struct {
	CIDR     string
	Port     int32  // 0 means "no port"
	Protocol string // "TCP" / "UDP"
	Comment  string
}

// Settings holds all policy-generation tuning.
type Settings struct {
	AllowDomains []string          // wildcard patterns to always allow, e.g. "*.auth0.com"
	PinDomains   []string          // domains to never turn into a wildcard
	KnownIPs     map[string]string // ip -> domain/pattern override
	ExtraEgress  []ExtraEgress     // always-allowed destinations
}

// New builds Settings from the raw repeatable flag values.
func New(allowDomain, pinDomain, knownIP, allowExtra []string) Settings {
	known := map[string]string{}
	for _, item := range knownIP {
		ip, domain, _ := strings.Cut(item, "=")
		ip, domain = strings.TrimSpace(ip), strings.TrimSpace(domain)
		if ip != "" && domain != "" {
			known[ip] = domain
		}
	}
	var extra []ExtraEgress
	for _, item := range allowExtra {
		if e, ok := ParseCIDRPort(item); ok {
			extra = append(extra, e)
		}
	}
	return Settings{
		AllowDomains: append([]string(nil), allowDomain...),
		PinDomains:   append([]string(nil), pinDomain...),
		KnownIPs:     known,
		ExtraEgress:  extra,
	}
}

var cidrPortRe = regexp.MustCompile(
	`^([^\s:#]+)(?::(\d+)(?:/(tcp|udp|TCP|UDP))?)?\s*(?:#\s*(.*))?$`)

// ParseCIDRPort parses "CIDR[:port[/tcp|udp]] [# comment]" into an ExtraEgress.
func ParseCIDRPort(value string) (ExtraEgress, bool) {
	m := cidrPortRe.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return ExtraEgress{}, false
	}
	e := ExtraEgress{CIDR: m[1]}
	if m[2] != "" {
		port, err := strconv.Atoi(m[2])
		if err != nil {
			return ExtraEgress{}, false
		}
		e.Port = int32(port)
		proto := strings.ToUpper(m[3])
		if proto == "" {
			proto = "TCP"
		}
		e.Protocol = proto
	}
	if m[4] != "" {
		e.Comment = m[4]
	}
	return e, true
}

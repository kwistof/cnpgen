// Package model holds the shared data model that stages pass between each
// other: the connection graph produced by collect (the pivot of the whole
// pipeline) and the IP->FQDN resolve index.
package model

// Endpoint identifies a flow endpoint by canonical app + namespace.
type Endpoint struct {
	App       string // canonical app string from labels.GetApp, or ""
	Namespace string // k8s namespace, or "" for external/reserved
}

// AppConn keys an app-to-app connection: a peer endpoint plus port/proto.
type AppConn struct {
	Peer  Endpoint
	Port  int32  // 0 means "no port"
	Proto string // "TCP" / "UDP" / ""
}

// ExtConn keys an external (world) connection by IP plus port/proto.
type ExtConn struct {
	IP    string
	Port  int32
	Proto string
}

// ConnBucket holds the egress/ingress connection counters for one endpoint.
type ConnBucket struct {
	EgressApps     map[AppConn]int // to in-cluster apps / reserved entities
	EgressExternal map[ExtConn]int // to reserved:world IPs
	IngressApps    map[AppConn]int // from in-cluster apps
}

func newBucket() *ConnBucket {
	return &ConnBucket{
		EgressApps:     map[AppConn]int{},
		EgressExternal: map[ExtConn]int{},
		IngressApps:    map[AppConn]int{},
	}
}

// Merge folds another bucket's counters into this one.
func (b *ConnBucket) Merge(other *ConnBucket) {
	for k, v := range other.EgressApps {
		b.EgressApps[k] += v
	}
	for k, v := range other.EgressExternal {
		b.EgressExternal[k] += v
	}
	for k, v := range other.IngressApps {
		b.IngressApps[k] += v
	}
}

// ConnGraph maps an (app, namespace) endpoint to its ConnBucket.
type ConnGraph struct {
	buckets map[Endpoint]*ConnBucket
}

// NewConnGraph returns an empty graph.
func NewConnGraph() *ConnGraph {
	return &ConnGraph{buckets: map[Endpoint]*ConnBucket{}}
}

// Bucket returns (creating if needed) the bucket for app/namespace.
func (g *ConnGraph) Bucket(app, namespace string) *ConnBucket {
	key := Endpoint{App: app, Namespace: namespace}
	b := g.buckets[key]
	if b == nil {
		b = newBucket()
		g.buckets[key] = b
	}
	return b
}

// Buckets returns the underlying map (read-only use).
func (g *ConnGraph) Buckets() map[Endpoint]*ConnBucket {
	return g.buckets
}

// Len returns the number of endpoints in the graph.
func (g *ConnGraph) Len() int { return len(g.buckets) }

// ResolvedFqdn is the result of correlating an external IP to one or more
// FQDNs.
type ResolvedFqdn struct {
	IP      string
	Fqdns   map[string]struct{} // candidate FQDNs for this IP
	Source  string              // fqdn-cache | flow-l7 | config | unresolved
	Comment string              // optional annotation for a toCIDR fallback
}

// Resolved reports whether any FQDN was found for the IP.
func (r *ResolvedFqdn) Resolved() bool { return len(r.Fqdns) > 0 }

// ResolveIndex is the full IP<->FQDN correlation plus the raw fqdn->ips cache.
type ResolveIndex struct {
	IPToFqdns map[string]*ResolvedFqdn       // ip -> ResolvedFqdn
	FqdnToIPs map[string]map[string]struct{} // fqdn -> set(ips)
}

// NewResolveIndex returns an empty index.
func NewResolveIndex() *ResolveIndex {
	return &ResolveIndex{
		IPToFqdns: map[string]*ResolvedFqdn{},
		FqdnToIPs: map[string]map[string]struct{}{},
	}
}

// ResolvedFor returns the ResolvedFqdn for an IP, or nil.
func (idx *ResolveIndex) ResolvedFor(ip string) *ResolvedFqdn {
	return idx.IPToFqdns[ip]
}

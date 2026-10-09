package verifycmd

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/labels"
	"github.com/kwistof/cnpgen/internal/ui"
)

// Looking up who holds an IP Cilium has no identity for (reserved:world)
// costs one API call, so answers are cached, but briefly: pod IPs are reused
// as soon as a pod goes away. The rate limit also bounds the cache: no more
// than ipLookupBurst + ipLookupRate*ipInfoTTL answers can be live at once.
// ipInfoMax is a hard cap on top of that.
const (
	ipInfoTTL       = time.Minute
	ipInfoMax       = 1024
	ipLookupRate    = rate.Limit(1) // per second
	ipLookupBurst   = 10
	ipLookupTimeout = 5 * time.Second
)

// cgnat is 100.64.0.0/10, used as a pod range by some clusters (e.g. AKS
// overlay). netip's IsPrivate doesn't cover it.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// podLister is the part of kube.Client ipInfo needs.
type podLister interface {
	PodsWithIP(ctx context.Context, ip string) ([]kube.PodRef, error)
}

// ipInfo says which pod or node holds an in-cluster IP Cilium reports as
// world, e.g. a pod Cilium doesn't manage, or none (a stale peer IP an app
// keeps retrying). It's only a hint for the log line: rules still use the IP.
type ipInfo struct {
	ctx      context.Context
	k        podLister
	limit    *rate.Limiter
	now      func() time.Time
	mu       sync.Mutex
	entries  map[string]ipEntry
	swept    time.Time
	disabled bool // lookups forbidden (RBAC): stop trying
}

type ipEntry struct {
	desc    string
	stale   bool // no running pod or node holds the IP
	expires time.Time
}

func newIPInfo(ctx context.Context, k podLister) *ipInfo {
	return &ipInfo{ctx: ctx, k: k, limit: rate.NewLimiter(ipLookupRate, ipLookupBurst),
		now: time.Now, entries: map[string]ipEntry{}}
}

// describe returns who holds ip (see lookup).
func (c *ipInfo) describe(ip string) string {
	desc, _ := c.lookup(ip)
	return desc
}

// lookup returns who holds ip, and stale when no running pod or node does,
// or "" when ip isn't private, the lookup failed, or the rate limit is
// reached (stale is then false: unknown). Safe for concurrent use; the API
// call runs without holding the lock.
func (c *ipInfo) lookup(ip string) (desc string, stale bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !(addr.IsPrivate() || cgnat.Contains(addr.Unmap())) {
		return "", false
	}
	c.mu.Lock()
	if c.disabled {
		c.mu.Unlock()
		return "", false
	}
	if e, ok := c.entries[ip]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.desc, e.stale
	}
	c.mu.Unlock()

	if !c.limit.Allow() {
		return "", false
	}
	ctx, cancel := context.WithTimeout(c.ctx, ipLookupTimeout)
	pods, err := c.k.PodsWithIP(ctx, ip)
	cancel()
	if err != nil {
		if apierrors.IsForbidden(err) {
			c.mu.Lock()
			if !c.disabled {
				c.disabled = true
				ui.Warn("can't list pods cluster-wide (%v): IPs Cilium has no identity for won't be looked up", err)
			}
			c.mu.Unlock()
		} else if c.ctx.Err() == nil {
			ui.Log("looking up pods with IP %s: %v", ip, err)
		}
		return "", false
	}
	desc, stale = describePods(pods)
	c.store(ip, ipEntry{desc: desc, stale: stale})
	return desc, stale
}

// store caches e for ip, dropping expired entries at most once per TTL,
// and not caching at all past ipInfoMax.
func (c *ipInfo) store(ip string, e ipEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Sub(c.swept) >= ipInfoTTL || len(c.entries) >= ipInfoMax {
		c.swept = now
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) >= ipInfoMax {
		return
	}
	e.expires = now.Add(ipInfoTTL)
	c.entries[ip] = e
}

// describePods sums up who holds an IP: the pod using it, else the node
// (hostNetwork pods share their node's IP), else a pod that finished (its
// status keeps the IP after it's released), else no one. stale is true in
// the last two cases.
func describePods(pods []kube.PodRef) (desc string, stale bool) {
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].Namespace != pods[j].Namespace {
			return pods[i].Namespace < pods[j].Namespace
		}
		return pods[i].Name < pods[j].Name
	})
	var running, done []kube.PodRef
	node := ""
	for _, p := range pods {
		switch {
		case p.Done:
			done = append(done, p)
		case p.HostNetwork:
			if node == "" {
				node = p.Node
			}
		default:
			running = append(running, p)
		}
	}
	switch {
	case len(running) > 0:
		s := "pod " + podDesc(running[0]) + ", unknown to Cilium"
		if len(running) > 1 {
			s += fmt.Sprintf(", +%d more", len(running)-1)
		}
		return s, false
	case node != "":
		return "node " + node, false
	case len(done) > 0:
		return "only finished pod " + podDesc(done[0]) + " had it, stale?", true
	default:
		return "no pod has this IP: stale, or outside the cluster?", true
	}
}

func podDesc(p kube.PodRef) string {
	s := p.Namespace + "/" + p.Name
	lbls := make([]string, 0, len(p.Labels))
	for k, v := range p.Labels {
		lbls = append(lbls, "k8s:"+k+"="+v)
	}
	if app := labels.GetApp(lbls); app != "" {
		s += ", " + strings.TrimPrefix(app, "k8s:")
	}
	return s
}

package verifycmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
)

type fakePods struct {
	pods  map[string][]kube.PodRef
	err   error
	calls int
}

func (f *fakePods) PodsWithIP(_ context.Context, ip string) ([]kube.PodRef, error) {
	f.calls++
	return f.pods[ip], f.err
}

func testIPInfo(k podLister) (*ipInfo, *time.Time) {
	c := newIPInfo(context.Background(), k)
	c.limit = rate.NewLimiter(rate.Inf, 0)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestDescribePods(t *testing.T) {
	back := kube.PodRef{Namespace: "webshop", Name: "hybris-back-1", Labels: map[string]string{"app.kubernetes.io/name": "hybris-back"}}
	cases := []struct {
		name string
		pods []kube.PodRef
		want string
	}{
		{"pod", []kube.PodRef{back}, "pod webshop/hybris-back-1, app.kubernetes.io/name=hybris-back, unknown to Cilium"},
		{"node", []kube.PodRef{{Namespace: "kube-system", Name: "kube-proxy-x", Node: "aks-1", HostNetwork: true}}, "node aks-1"},
		{"running pod beats a finished one", []kube.PodRef{{Namespace: "a", Name: "job-1", Done: true}, back}, "pod webshop/hybris-back-1"},
		{"finished pod only", []kube.PodRef{{Namespace: "a", Name: "job-1", Done: true}}, "only finished pod a/job-1 had it, stale?"},
		{"nobody", nil, "no pod has this IP"},
	}
	for _, c := range cases {
		if got := describePods(c.pods); !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: got %q, want prefix %q", c.name, got, c.want)
		}
	}
}

func TestIPInfoCachesBriefly(t *testing.T) {
	k := &fakePods{}
	c, now := testIPInfo(k)
	if got := c.describe("172.16.80.183"); !strings.HasPrefix(got, "no pod") {
		t.Fatalf("got %q", got)
	}
	c.describe("172.16.80.183")
	if k.calls != 1 {
		t.Fatalf("calls = %d, want 1 (cached)", k.calls)
	}
	// The IP is reassigned: once the entry expires, the new owner shows.
	k.pods = map[string][]kube.PodRef{"172.16.80.183": {{Namespace: "n", Name: "p"}}}
	*now = now.Add(ipInfoTTL)
	if got := c.describe("172.16.80.183"); !strings.HasPrefix(got, "pod n/p") {
		t.Fatalf("after TTL got %q", got)
	}
}

func TestIPInfoBounded(t *testing.T) {
	k := &fakePods{}
	c, now := testIPInfo(k)
	for i := 0; i < ipInfoMax+50; i++ {
		c.describe(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if len(c.entries) != ipInfoMax {
		t.Fatalf("entries = %d, want cap %d", len(c.entries), ipInfoMax)
	}
	// Expired entries are dropped on the next store.
	*now = now.Add(ipInfoTTL)
	c.describe("10.9.9.9")
	if len(c.entries) != 1 {
		t.Fatalf("entries after expiry = %d, want 1", len(c.entries))
	}
}

func TestIPInfoSkipsPublicAndRateLimits(t *testing.T) {
	k := &fakePods{}
	c, _ := testIPInfo(k)
	if got := c.describe("93.184.216.34"); got != "" || k.calls != 0 {
		t.Fatalf("public IP looked up: %q, %d calls", got, k.calls)
	}
	c.describe("100.64.1.1") // CGNAT pod range
	if k.calls != 1 {
		t.Fatalf("CGNAT IP not looked up")
	}
	c.limit = rate.NewLimiter(0, 1)
	c.describe("10.1.1.1")
	if got := c.describe("10.1.1.2"); got != "" || k.calls != 2 {
		t.Fatalf("rate limit not applied: %q, %d calls", got, k.calls)
	}
}

func TestIPInfoStopsWhenForbidden(t *testing.T) {
	k := &fakePods{err: apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("no"))}
	c, _ := testIPInfo(k)
	c.describe("10.1.1.1")
	c.describe("10.1.1.2")
	if k.calls != 1 {
		t.Fatalf("calls = %d, want 1 (disabled after Forbidden)", k.calls)
	}
	// Other errors aren't cached: the next flow retries.
	k2 := &fakePods{err: errors.New("timeout")}
	c2, _ := testIPInfo(k2)
	c2.describe("10.1.1.1")
	c2.describe("10.1.1.1")
	if k2.calls != 2 {
		t.Fatalf("calls = %d, want 2", k2.calls)
	}
}

func TestLogLineNotesWorldPeer(t *testing.T) {
	f := tcpFlow(frontend, world, "EGRESS", "172.16.80.183", 7801)
	pk := peerKey{dir: "egress", kind: "cidr", value: "172.16.80.183/32"}
	got := logLine(f, pk, portKey{7801, "TCP"}, false, "", "node aks-1")
	if !strings.Contains(got, "-> 172.16.80.183 (node aks-1)  7801/TCP") {
		t.Fatalf("got %q", got)
	}
}

func TestPodWithoutAppLabel(t *testing.T) {
	w := testWatcher(t, nil)
	solr := hubble.Endpoint{Namespace: "solr", PodName: "solr-op-0", Labels: []string{
		"k8s:control-plane=solr-operator",
		"k8s:io.cilium.k8s.policy.serviceaccount=default",
		"k8s:io.kubernetes.pod.namespace=solr",
	}}
	pk := w.peer(solr, "10.244.3.3", 0, nil)
	if pk.kind != "endpoint" || pk.value != "k8s:control-plane=solr-operator" || pk.ns != "solr" {
		t.Fatalf("peer = %+v", pk)
	}
	if got := describe(solr, "10.244.3.3"); got != "solr-op-0.solr" {
		t.Fatalf("describe = %q", got)
	}
}

func TestIPInfoConcurrent(t *testing.T) {
	c := newIPInfo(context.Background(), &lockedPods{})
	c.limit = rate.NewLimiter(rate.Inf, 0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.describe(fmt.Sprintf("10.0.%d.%d", g, i))
			}
		}()
	}
	wg.Wait()
}

// lockedPods is a fakePods safe for concurrent calls.
type lockedPods struct {
	mu sync.Mutex
	fakePods
}

func (l *lockedPods) PodsWithIP(ctx context.Context, ip string) ([]kube.PodRef, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakePods.PodsWithIP(ctx, ip)
}

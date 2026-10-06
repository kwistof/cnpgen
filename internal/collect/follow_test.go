package collect

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
)

// fakeCluster stands in for kube.Client's CiliumPods/ExecStream.
type fakeCluster struct {
	mu    sync.Mutex
	pods  []kube.Pod
	execs map[string][][]string                // argv of every exec, by pod
	fail  map[string]func(argv []string) error // pod -> error to fail with, nil to stream
	line  string                               // written once by a healthy stream
}

func newFakeCluster(pods ...string) *fakeCluster {
	c := &fakeCluster{execs: map[string][][]string{}, fail: map[string]func([]string) error{}}
	c.setPods(pods...)
	return c
}

func (c *fakeCluster) setPods(names ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pods = nil
	for _, n := range names {
		c.pods = append(c.pods, kube.Pod{Name: n, Node: "node-" + n})
	}
}

func (c *fakeCluster) list(context.Context) ([]kube.Pod, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]kube.Pod(nil), c.pods...), nil
}

func (c *fakeCluster) exec(ctx context.Context, pod string, argv []string, w io.Writer) error {
	c.mu.Lock()
	c.execs[pod] = append(c.execs[pod], argv)
	fail := c.fail[pod]
	line := c.line
	c.mu.Unlock()
	if fail != nil {
		if err := fail(argv); err != nil {
			return err
		}
	}
	if line != "" {
		_, _ = io.WriteString(w, line+"\n")
	}
	<-ctx.Done()
	return nil
}

func (c *fakeCluster) count(pod string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.execs[pod])
}

func (c *fakeCluster) argv(pod string, i int) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.execs[pod][i]
}

// fastTimings shrinks the supervisor timings for the test's duration.
func fastTimings(t *testing.T) {
	t.Helper()
	old := []time.Duration{rescanEvery, retryMin, retryMax, healthyAfter, upAfter, forgetAfter}
	rescanEvery, retryMin, retryMax, healthyAfter, upAfter, forgetAfter =
		5*time.Millisecond, 20*time.Millisecond, 80*time.Millisecond, time.Hour, time.Hour, 50*time.Millisecond
	t.Cleanup(func() {
		rescanEvery, retryMin, retryMax, healthyAfter, upAfter, forgetAfter = old[0], old[1], old[2], old[3], old[4], old[5]
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func run(t *testing.T, c *fakeCluster, opts FollowOptions, onFlow func(*hubble.Flow)) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if onFlow == nil {
		onFlow = func(*hubble.Flow) {}
	}
	f, err := startSupervisor(ctx, c.list, c.exec, opts, onFlow)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		cancel()
		f.Wait()
	}
}

func TestFollowPicksUpNewAgentPods(t *testing.T) {
	fastTimings(t)
	c := newFakeCluster("cilium-a")
	stop := run(t, c, FollowOptions{}, nil)
	defer stop()

	waitFor(t, "stream on cilium-a", func() bool { return c.count("cilium-a") == 1 })
	c.setPods("cilium-a", "cilium-b") // a node joined
	waitFor(t, "stream on new cilium-b", func() bool { return c.count("cilium-b") == 1 })
	time.Sleep(30 * time.Millisecond)
	if n := c.count("cilium-a"); n != 1 {
		t.Fatalf("healthy stream on cilium-a restarted: %d execs", n)
	}
}

func TestFollowRetriesLostStreamWithBackoff(t *testing.T) {
	fastTimings(t)
	c := newFakeCluster("cilium-a")
	c.fail["cilium-a"] = func([]string) error { return errors.New(`pods "node-a" not found`) }
	stop := run(t, c, FollowOptions{}, nil)
	defer stop()

	waitFor(t, "a few retries", func() bool { return c.count("cilium-a") >= 3 })
	stop()
	// Backoff 20, 40, 80, 80 ms: in the ~150 ms to reach 3 attempts, no
	// steady 5 ms rescan-paced hammering.
	if n := c.count("cilium-a"); n > 5 {
		t.Fatalf("retried %d times: backoff not applied", n)
	}
}

func TestFollowForgetsRemovedPods(t *testing.T) {
	fastTimings(t)
	c := newFakeCluster("cilium-a", "cilium-b")
	c.fail["cilium-a"] = func([]string) error { return errors.New("connection lost") }
	stop := run(t, c, FollowOptions{}, nil)
	defer stop()

	waitFor(t, "first attempt", func() bool { return c.count("cilium-a") >= 1 })
	c.setPods("cilium-b") // node removed along with its agent pod
	time.Sleep(150 * time.Millisecond)
	n := c.count("cilium-a")
	time.Sleep(150 * time.Millisecond)
	if c.count("cilium-a") != n {
		t.Fatal("a pod no longer listed is still being retried")
	}
}

func TestFollowResumesPodBackFromNotReady(t *testing.T) {
	fastTimings(t)
	c := newFakeCluster("cilium-a")
	down := true
	c.fail["cilium-a"] = func([]string) error {
		if down {
			return errors.New("dial tcp 192.168.97.3:10250: connect: no route to host")
		}
		return nil
	}
	stop := run(t, c, FollowOptions{}, nil)
	defer stop()

	waitFor(t, "first failure", func() bool { return c.count("cilium-a") >= 1 })
	c.setPods() // node down: agent pod marked not ready, so not listed
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	down = false
	c.mu.Unlock()
	n := c.count("cilium-a")
	c.setPods("cilium-a") // node back
	waitFor(t, "stream restarted on the same pod", func() bool { return c.count("cilium-a") > n })
}

func TestFollowDropsCELOnlyWhenRejected(t *testing.T) {
	fastTimings(t)
	hasCEL := func(argv []string) bool { return strings.Contains(strings.Join(argv, " "), "--cel-expression") }

	// Unrelated failure: retried later, still with the filter.
	c := newFakeCluster("cilium-a")
	first := true
	c.fail["cilium-a"] = func([]string) error {
		if first {
			first = false
			return errors.New(`pods "node-a" not found`)
		}
		return nil
	}
	stop := run(t, c, FollowOptions{CEL: "true"}, nil)
	waitFor(t, "retry", func() bool { return c.count("cilium-a") >= 2 })
	stop()
	if !hasCEL(c.argv("cilium-a", 1)) {
		t.Fatalf("filter dropped after an unrelated failure: %v", c.argv("cilium-a", 1))
	}

	// Rejected filter: retried right away without it.
	c = newFakeCluster("cilium-a")
	c.fail["cilium-a"] = func(argv []string) error {
		if hasCEL(argv) {
			return errors.New("command terminated with exit code 1: Error compiling CEL expression: ERROR: <input>:1:6\n | .....^")
		}
		return nil
	}
	stop = run(t, c, FollowOptions{CEL: "bogus"}, nil)
	defer stop()
	waitFor(t, "unfiltered retry", func() bool { return c.count("cilium-a") >= 2 })
	if hasCEL(c.argv("cilium-a", 1)) {
		t.Fatalf("filter kept after Hubble rejected it: %v", c.argv("cilium-a", 1))
	}
}

func TestFollowKeepAndParse(t *testing.T) {
	fastTimings(t)
	c := newFakeCluster("cilium-a")
	c.line = `{"flow":{"source":{"labels":["k8s:app=a"]},"destination":{"labels":["k8s:app=b"]},"policy_match_type":4}}`
	var mu sync.Mutex
	var got []*hubble.Flow
	stop := run(t, c, FollowOptions{Keep: func(l []byte) bool { return strings.Contains(string(l), "policy_match_type") }},
		func(f *hubble.Flow) { mu.Lock(); got = append(got, f); mu.Unlock() })
	defer stop()
	waitFor(t, "a flow", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 1 })
	if got[0].PolicyMatchType != 4 {
		t.Fatalf("parsed %+v", got[0])
	}
}

func TestIsCELRejection(t *testing.T) {
	for msg, want := range map[string]bool{
		"command terminated with exit code 1: Error compiling CEL expression: ERROR": true,
		"command terminated with exit code 1: unknown flag: --cel-expression":        true,
		`pods "aks-npmfeg-19706424-vmss0000m4" not found`:                            false,
		"error dialing backend: EOF":                                                 false,
	} {
		if got := isCELRejection(errors.New(msg)); got != want {
			t.Errorf("%q: got %v, want %v", msg, got, want)
		}
	}
}

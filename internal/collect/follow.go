package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/ui"
)

// Timings of the follow supervisor. Variables so tests can shrink them.
var (
	// rescanEvery is how often the Cilium agent pods are re-listed, to start
	// streams on new pods (node added, agent pod replaced) and retry lost
	// ones.
	rescanEvery = 15 * time.Second
	// retryMin/retryMax bound the backoff before re-streaming from a pod
	// whose stream failed. It doubles on each failure in a row: each retry
	// that gets as far as starting hubble leaves one more unkillable
	// `hubble observe --follow` behind in the agent (see StartFollowWith), so
	// a pod that keeps failing must not be retried at a steady pace.
	retryMin = 15 * time.Second
	retryMax = 5 * time.Minute
	// healthyAfter is how long a stream must have run for its next failure
	// to count as a first one again (backoff reset).
	healthyAfter = time.Minute
	// upAfter is how long a restarted stream must stay up, if it outputs
	// nothing before, to be reported as resumed: a failing exec errors out
	// within seconds, while a healthy, filtered stream can be silent for long.
	upAfter = 10 * time.Second
	// forgetAfter is how long a pod can stay unlisted (deleted, or not ready
	// because its node is down) before the supervisor drops its state.
	forgetAfter = time.Hour
)

// Follower keeps one `hubble observe --follow` exec alive per Cilium agent
// pod for as long as ctx lives, following the agent pods as they come and go.
// Every parsed flow is pushed to onFlow as it arrives; callers that need a
// bounded window (e.g. one audit round) filter/collect from onFlow themselves
// rather than starting a new exec per window.
type Follower struct {
	wg sync.WaitGroup
}

// FollowOptions narrows what a Follower streams.
type FollowOptions struct {
	// Label restricts the stream to flows from or to pods with this
	// "key=value" label; "" streams every flow on the node.
	Label string
	// CEL is a Hubble --cel-expression applied in the agent, so filtered-out
	// flows never cross the exec connection. If an agent's Hubble rejects
	// it, that pod's stream restarts without it and Keep alone does the
	// filtering.
	CEL string
	// Keep, if set, is called on each raw JSON line before it's parsed;
	// lines it rejects are dropped without allocating a Flow. It must be
	// safe for concurrent use.
	Keep func(line []byte) bool
}

// StartFollow starts the persistent per-pod streams for label and returns
// immediately; call Wait to block until ctx is cancelled and every stream has
// torn down.
func StartFollow(ctx context.Context, k *kube.Client, label string, onFlow func(*hubble.Flow)) (*Follower, error) {
	return StartFollowWith(ctx, k, FollowOptions{Label: label}, onFlow)
}

// StartFollowWith is StartFollow with filtering options.
//
// The Cilium agent pods are re-listed every rescanEvery: a stream is started
// on every new one, and a stream that stopped (agent restarted, node removed,
// connection lost) is retried with a backoff while its pod is still listed.
// A stream that stops is reported with a warning as soon as it does, and
// again when it resumes, so a watch that went blind can't pass for a quiet
// one.
//
// Known limitation: the remote `hubble observe --follow` process is not
// killed at teardown and keeps running in the agent container until that
// pod restarts. Cancelling the exec doesn't stop it (no TTY, and hubble
// ignores its stdout going away; a TTY doesn't help either), and killing it
// needs a binary (sh, kill, pkill) that minimal Cilium agent images, like
// AKS's, don't ship.
func StartFollowWith(ctx context.Context, k *kube.Client, opts FollowOptions, onFlow func(*hubble.Flow)) (*Follower, error) {
	return startSupervisor(ctx, k.CiliumPods, k.ExecStream, opts, onFlow)
}

// listPods and execStream are kube.Client's CiliumPods and ExecStream.
type (
	listPods   func(ctx context.Context) ([]kube.Pod, error)
	execStream func(ctx context.Context, pod string, argv []string, w io.Writer) error
)

// podStream is the supervisor's state for one Cilium agent pod.
type podStream struct {
	pod      kube.Pod
	running  bool
	cel      string    // CEL filter still in use for this pod ("" once rejected)
	failures int       // stream failures in a row
	nextTry  time.Time // earliest restart after a failure
	down     bool      // a stop was reported and no resume yet
	appeared bool      // listed after startup (a new agent pod)
	everUp   bool      // a stream on it has been up at least once
	unlisted time.Time // when it stopped being listed, zero while listed
	said     bool      // its unlisting was reported
}

type supervisor struct {
	list   listPods
	exec   execStream
	opts   FollowOptions
	onFlow func(*hubble.Flow)
	f      *Follower

	mu      sync.Mutex
	streams map[string]*podStream // by pod name
}

func startSupervisor(ctx context.Context, list listPods, exec execStream, opts FollowOptions, onFlow func(*hubble.Flow)) (*Follower, error) {
	pods, err := list(ctx)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		ui.Warn("No cilium pods found yet; watching for them to appear.")
	}
	s := &supervisor{list: list, exec: exec, opts: opts, onFlow: onFlow,
		f: &Follower{}, streams: map[string]*podStream{}}
	s.reconcile(ctx, pods, true)
	s.f.wg.Add(1)
	go func() {
		defer s.f.wg.Done()
		s.loop(ctx)
	}()
	return s.f, nil
}

func (s *supervisor) loop(ctx context.Context) {
	tick := time.NewTicker(rescanEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		pods, err := s.list(ctx)
		if err != nil {
			if ctx.Err() == nil {
				ui.Log("re-listing cilium pods: %v", err)
			}
			continue
		}
		s.reconcile(ctx, pods, false)
	}
}

// reconcile starts streams on pods not streamed yet, retries stopped ones
// whose backoff is over, and tracks pods no longer listed: deleted, or not
// ready because their node is down. Those come back under the same name
// when their node does, or are replaced by a new pod.
func (s *supervisor) reconcile(ctx context.Context, pods []kube.Pod, initial bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	listed := make(map[string]bool, len(pods))
	now := time.Now()
	for _, pod := range pods {
		listed[pod.Name] = true
		ps := s.streams[pod.Name]
		if ps == nil {
			ps = &podStream{pod: pod, cel: s.opts.CEL, appeared: !initial}
			s.streams[pod.Name] = ps
		}
		if !ps.unlisted.IsZero() {
			// Back (node up again): no need to wait out the backoff.
			ps.unlisted, ps.said, ps.nextTry = time.Time{}, false, time.Time{}
		}
		if ps.running || now.Before(ps.nextTry) {
			continue
		}
		s.start(ctx, ps)
	}
	for name, ps := range s.streams {
		if listed[name] || ps.running {
			continue
		}
		if ps.unlisted.IsZero() {
			ps.unlisted = now
		}
		if ps.down && !ps.said {
			ps.said = true
			fmt.Println(ui.Dim(fmt.Sprintf("  %s (%s) is no longer a running Cilium agent (deleted, or its node is down); "+
				"watching for it or a replacement to come up.", ps.pod.Name, ps.pod.Node)))
		}
		if now.Sub(ps.unlisted) >= forgetAfter {
			delete(s.streams, name)
		}
	}
}

// start runs one stream for ps in the background. The caller holds s.mu.
func (s *supervisor) start(ctx context.Context, ps *podStream) {
	ps.running = true
	s.f.wg.Add(1)
	go func() {
		defer s.f.wg.Done()
		begin := time.Now()
		for {
			s.mu.Lock()
			cel := ps.cel
			s.mu.Unlock()
			resumed := func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				if !ps.everUp {
					ps.everUp = true
					if ps.appeared {
						fmt.Println(ui.Dim(fmt.Sprintf("  Now also watching %s (%s), a Cilium agent that came up since the start.",
							ps.pod.Name, ps.pod.Node)))
					}
				}
				if ps.down {
					ps.down = false
					fmt.Println(ui.Green(fmt.Sprintf("  Flow watch on %s (%s) resumed.", ps.pod.Name, ps.pod.Node)))
				}
			}
			upTimer := time.AfterFunc(upAfter, resumed)
			err := followPod(ctx, s.exec, ps.pod, observeCmd(s.opts.Label, 0, true, cel), s.opts.Keep, resumed, s.onFlow)
			upTimer.Stop()
			if err != nil && cel != "" && isCELRejection(err) && ctx.Err() == nil {
				first, _, _ := strings.Cut(err.Error(), "\n") // later lines point at a column
				ui.Warn("hubble on %s (%s) rejected the server-side filter, filtering in cnpgen instead: %s",
					ps.pod.Name, ps.pod.Node, first)
				s.mu.Lock()
				ps.cel = ""
				s.mu.Unlock()
				continue
			}
			s.ended(ctx, ps, begin, err)
			return
		}
	}()
}

// ended records a stream's end and schedules its retry.
func (s *supervisor) ended(ctx context.Context, ps *podStream, begin time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps.running = false
	if ctx.Err() != nil {
		return // normal teardown
	}
	if time.Since(begin) >= healthyAfter {
		ps.failures = 0
	}
	ps.failures++
	delay := retryMin << (ps.failures - 1)
	if delay > retryMax || delay <= 0 {
		delay = retryMax
	}
	ps.nextTry = time.Now().Add(delay)

	reason := "stream ended"
	if err != nil {
		reason = lastLine(err.Error())
	}
	if ps.appeared && !ps.everUp {
		// A new agent pod whose Hubble isn't serving yet: expected, quiet.
		ui.Log("flow watch on new %s (%s) not up yet, retrying in %s: %s", ps.pod.Name, ps.pod.Node, delay, reason)
		return
	}
	if ps.down {
		ui.Log("flow watch on %s (%s) still failing, retrying in %s: %s", ps.pod.Name, ps.pod.Node, delay, reason)
		return
	}
	ps.down = true
	ui.Warn("flow watch stopped on %s (%s), its node's traffic isn't watched until it reconnects (retrying in %s): %s",
		ps.pod.Name, ps.pod.Node, delay.Round(time.Second), reason)
}

// isCELRejection reports whether a hubble exec failed because it doesn't
// accept the --cel-expression filter (too old a Hubble, or a server that
// can't compile it), rather than for any other reason.
func isCELRejection(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "cel expression") || strings.Contains(s, "cel-expression")
}

// followPod runs one `hubble observe --follow` exec until it ends, feeding
// onFlow. onOutput is called once, on its first line of output.
func followPod(ctx context.Context, exec execStream, pod kube.Pod, argv []string, keep func([]byte) bool, onOutput func(), onFlow func(*hubble.Flow)) error {
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		saw := false
		for sc.Scan() {
			if !saw {
				saw = true
				onOutput()
			}
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 || (keep != nil && !keep(line)) {
				continue
			}
			fl, perr := hubble.ParseLine(line)
			if perr != nil || fl == nil {
				continue
			}
			onFlow(fl)
		}
		// Keep draining so the exec never blocks on a full pipe.
		_, _ = io.Copy(io.Discard, pr)
		close(done)
	}()
	err := exec(ctx, pod.Name, argv, pw)
	pw.Close()
	<-done
	return err
}

// Wait blocks until every per-pod stream has torn down (i.e. until the ctx
// passed to StartFollow is cancelled).
func (f *Follower) Wait() {
	f.wg.Wait()
}

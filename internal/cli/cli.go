// Package cli parses flags and dispatches to the two subcommands:
//
//	audit     watch live traffic and produce a working policy (the main path)
//	generate  build policy files offline from a saved flows file
//
// -l/--label plus -n/--namespace together select which pods' traffic to
// watch (mandatory label, namespace defaults to "default"); -n is also where
// the generated CiliumNetworkPolicy objects are written/deployed, since a CNP
// only ever matches pods in its own namespace. Everything is a flag; there is
// no config file.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kwistof/cnpgen/internal/audit"
	"github.com/kwistof/cnpgen/internal/collect"
	"github.com/kwistof/cnpgen/internal/deploy"
	"github.com/kwistof/cnpgen/internal/generate"
	"github.com/kwistof/cnpgen/internal/hubble"
	"github.com/kwistof/cnpgen/internal/kube"
	"github.com/kwistof/cnpgen/internal/pipeline"
	"github.com/kwistof/cnpgen/internal/policyindex"
	"github.com/kwistof/cnpgen/internal/resolve"
	"github.com/kwistof/cnpgen/internal/review"
	"github.com/kwistof/cnpgen/internal/settings"
	"github.com/kwistof/cnpgen/internal/ui"
	"github.com/kwistof/cnpgen/internal/verifycmd"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// labelFlag is -l/--label: repeatable, it collects every value into labels,
// and label holds the last one for the commands that take a single label
// (requireTarget rejects more there).
type labelFlag struct{ g *globalFlags }

func (f labelFlag) String() string {
	if f.g == nil {
		return ""
	}
	return f.g.label
}
func (f labelFlag) Set(v string) error {
	f.g.labels = append(f.g.labels, v)
	f.g.label = v
	return nil
}

// globalFlags are shared by both subcommands.
type globalFlags struct {
	context         string
	kubeconfig      string
	ciliumNamespace string
	ciliumSelector  string
	nodes           stringList
	debug           bool
	noBanner        bool

	label       string
	labels      []string // every -l given; see labelFlag
	namespace   string
	output      string
	allowDomain stringList
	pinDomain   stringList
	knownIP     stringList
	allowExtra  stringList
	accept      bool
	seedPolicy  string
}

func (g *globalFlags) register(fs *flag.FlagSet) {
	fs.Var(labelFlag{g}, "l", "pods to watch, by label, e.g. app.kubernetes.io/name=foo (required)")
	fs.Var(labelFlag{g}, "label", "pods to watch, by label, e.g. app.kubernetes.io/name=foo (required)")
	fs.StringVar(&g.namespace, "n", "default", "namespace to watch pods in and write/deploy the policy into")
	fs.StringVar(&g.namespace, "namespace", "default", "namespace to watch pods in and write/deploy the policy into")
	fs.StringVar(&g.output, "o", "netpol-out", "output directory for the generated policy files")
	fs.StringVar(&g.output, "output", "netpol-out", "output directory for the generated policy files")

	fs.Var(&g.allowDomain, "allow-domain", "always allow this domain as a wildcard, e.g. '*.auth0.com' (repeatable)")
	fs.Var(&g.pinDomain, "pin-domain", "never turn this exact domain into a wildcard (repeatable)")
	fs.Var(&g.knownIP, "known-ip", "map an IP cnpgen can't resolve to a domain: IP=DOMAIN (repeatable)")
	fs.Var(&g.allowExtra, "allow-extra", "always allow this destination: CIDR[:PORT[/tcp|udp]] (repeatable)")
	fs.BoolVar(&g.accept, "accept-suggestions", false, "emit suggested wildcard patterns instead of exact matchName")
	fs.StringVar(&g.seedPolicy, "seed-policy", "", "start from an existing CiliumNetworkPolicy file: its toFQDNs/toCIDR become a floor, kept regardless of what's observed")

	fs.StringVar(&g.context, "context", "", "kube context to use (default: current context)")
	fs.StringVar(&g.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: in-cluster, then ~/.kube/config)")
	fs.StringVar(&g.ciliumNamespace, "cilium-namespace", "kube-system", "namespace of the Cilium agent pods")
	fs.StringVar(&g.ciliumSelector, "cilium-selector", "k8s-app=cilium", "label selector for the Cilium agent pods")
	fs.Var(&g.nodes, "nodes", "restrict traffic collection to these node names (repeatable)")
	fs.BoolVar(&g.debug, "debug", false, "verbose debug logging to stderr")
	fs.BoolVar(&g.noBanner, "no-banner", false, "suppress the banner")
}

func (g *globalFlags) newSettings() settings.Settings {
	return settings.New(g.allowDomain, g.pinDomain, g.knownIP, g.allowExtra)
}

// loadSeed loads --seed-policy if given, or returns (nil, nil) if it wasn't.
func (g *globalFlags) loadSeed() (*generate.Seed, error) {
	if g.seedPolicy == "" {
		return nil, nil
	}
	return generate.LoadSeed(g.seedPolicy, g.label)
}

func (g *globalFlags) newKube() (*kube.Client, error) {
	return kube.New(kube.Options{
		Context:         g.context,
		Kubeconfig:      g.kubeconfig,
		CiliumNamespace: g.ciliumNamespace,
		CiliumSelector:  g.ciliumSelector,
		Nodes:           g.nodes,
	})
}

func showBanner(g *globalFlags) {
	if !g.noBanner {
		fmt.Fprint(os.Stderr, banner)
	}
}

// fail prints a red error line pointing at the fix and returns exit code 1.
func fail(format string, args ...any) int {
	fmt.Fprintln(os.Stderr, ui.Red("error: ")+fmt.Sprintf(format, args...))
	return 1
}

// Main is the entry point. Returns a process exit code.
func Main(argv []string) int {
	if len(argv) < 1 {
		usage()
		return 2
	}
	switch argv[0] {
	case "audit":
		return cmdAudit(argv[1:])
	case "verify":
		return cmdVerify(argv[1:])
	case "generate":
		return cmdGenerate(argv[1:])
	case "cleanup":
		return cmdCleanup(argv[1:])
	case "review":
		return cmdReview(argv[1:])
	case "version", "-v", "--version":
		fmt.Printf("cnpgen v%s\n", Version)
		return 0
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, ui.Red("error: ")+"unknown command %q\n\n", argv[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintln(os.Stderr, `Usage:
  cnpgen audit    -l <label> -n <namespace> [options]    watch live traffic and build a working policy
  cnpgen verify   -l <label> -n <namespace> [options]    read-only: log what the deployed policy blocks
  cnpgen verify   --all [-n <namespace>] [options]       same, for every policy at once
  cnpgen generate -l <label> -n <namespace> --flows <f>  build policy files offline from a saved flows file
  cnpgen cleanup  -n <namespace> [-l <label>]            delete cnpgen-managed policies from a namespace
  cnpgen review   [file|dir ...]                         choose which domain groups to allow as *.suffix wildcards
  cnpgen version                                         print the version

Quick start:
  cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace

  Watches traffic for the matching pods, writes a CiliumNetworkPolicy into
  netpol-out/, deploys it in safe (non-enforcing) mode, and repeats until
  nothing is missing. It never turns enforcement on: that stays your call.

  Already have a policy deployed? "cnpgen verify" logs every flow it blocks
  and writes the rules to add. Read-only.

Run "cnpgen audit -h", "cnpgen verify -h", or "cnpgen generate -h" for the full option list.`)
}

// printGrouped renders a subcommand's flags in labelled groups, so the help is
// scannable instead of one long alphabetical list.
func printGrouped(cmd, summary, example string, fs *flag.FlagSet, groups [][2]any) {
	fmt.Fprintf(os.Stderr, "%s\n\n", summary)
	fmt.Fprintf(os.Stderr, "Usage:\n  cnpgen %s [options]\n\n", cmd)
	if example != "" {
		fmt.Fprintf(os.Stderr, "Example:\n%s\n\n", example)
	}
	for _, grp := range groups {
		title := grp[0].(string)
		names := grp[1].([]string)
		fmt.Fprintf(os.Stderr, "%s:\n", title)
		for _, name := range names {
			f := fs.Lookup(name)
			if f == nil {
				continue
			}
			flagName := "-" + f.Name
			def := ""
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				def = fmt.Sprintf(" (default: %s)", f.DefValue)
			}
			fmt.Fprintf(os.Stderr, "  %-22s %s%s\n", flagName, f.Usage, def)
		}
		fmt.Fprintln(os.Stderr)
	}
}

func cmdAudit(argv []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	var g globalFlags
	g.register(fs)
	var flows, fqdnCache string
	var last, settle, duration int
	var dryRun bool
	fs.StringVar(&flows, "flows", "", "seed from this flows file instead of collecting recent traffic")
	fs.StringVar(&fqdnCache, "fqdn-cache", "", "resolve IPs from this saved *-fqdn dump instead of the live cache")
	fs.IntVar(&last, "last", 5000, "seed from the last N flows already seen (0 = start empty, live only)")
	fs.IntVar(&settle, "settle", 0, "stop once N rounds in a row see no new blocked traffic (0 = never auto-stop)")
	fs.IntVar(&duration, "duration", 120, "how many seconds to watch per round")
	fs.BoolVar(&dryRun, "dry-run", false, "preview the policy without touching the cluster")
	for _, name := range []string{"l", "label"} {
		fs.Lookup(name).Usage = "pods to watch, by label, e.g. app.kubernetes.io/name=foo (required; repeatable: " +
			"one policy per label, all sharing one flow stream per Cilium agent)"
	}

	fs.Usage = func() {
		printGrouped("audit",
			"Watch live traffic for the selected pods and build a working CiliumNetworkPolicy,\n"+
				"deployed in safe (non-enforcing) mode. Runs until you stop it (Ctrl+C) or it\n"+
				"settles. The deployed policy is removed at the end; the policy file is kept.",
			"  cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --settle 3\n"+
				"  cnpgen audit -l app.kubernetes.io/name=frontend -l app.kubernetes.io/name=backend -n my-namespace",
			fs, [][2]any{
				{"Target", []string{"l", "n"}},
				{"Run control", []string{"duration", "settle", "last", "dry-run", "o"}},
				{"Tuning", []string{"allow-domain", "pin-domain", "known-ip", "allow-extra", "accept-suggestions", "seed-policy"}},
				{"Offline input", []string{"flows", "fqdn-cache"}},
				{"Cluster", []string{"context", "kubeconfig", "cilium-namespace", "cilium-selector", "nodes"}},
				{"Misc", []string{"debug", "no-banner"}},
			})
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	ui.Debug = g.debug
	showBanner(&g)

	if code, ok := requireTarget(&g, true); !ok {
		return code
	}
	labels := dedupe(g.labels)
	if len(labels) > 1 && g.seedPolicy != "" {
		return fail("--seed-policy takes a single -l: it seeds the policy of one app")
	}

	cfg := g.newSettings()
	seed, err := g.loadSeed()
	if err != nil {
		return fail("%v", err)
	}
	k, err := g.newKube()
	if err != nil {
		return fail("%v", err)
	}

	// Ctrl+C cancels the context; the audit loop finalizes cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	initial, err := seedFlows(ctx, k, labels, flows, last)
	if err != nil {
		return fail("%v", err)
	}

	_, err = audit.Run(ctx, k, cfg, audit.Config{
		Labels:    labels,
		Namespace: g.namespace,
		OutDir:    g.output,
		Settle:    settle,
		Duration:  time.Duration(duration) * time.Second,
		Accept:    g.accept,
		DryRun:    dryRun,
		FqdnDump:  fqdnCache,
		Seed:      seed,
	}, initial)
	if err != nil {
		return fail("%v", err)
	}
	return 0
}

func cmdVerify(argv []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var g globalFlags
	fs.StringVar(&g.label, "l", "", "pods to watch, by label, e.g. app.kubernetes.io/name=foo (required)")
	fs.StringVar(&g.label, "label", "", "pods to watch, by label, e.g. app.kubernetes.io/name=foo (required)")
	fs.StringVar(&g.namespace, "n", "default", "namespace pods run in")
	fs.StringVar(&g.namespace, "namespace", "default", "namespace pods run in")
	fs.StringVar(&g.context, "context", "", "kube context to use (default: current context)")
	fs.StringVar(&g.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: in-cluster, then ~/.kube/config)")
	fs.StringVar(&g.ciliumNamespace, "cilium-namespace", "kube-system", "namespace of the Cilium agent pods")
	fs.StringVar(&g.ciliumSelector, "cilium-selector", "k8s-app=cilium", "label selector for the Cilium agent pods")
	fs.Var(&g.nodes, "nodes", "restrict traffic collection to these node names (repeatable)")
	fs.BoolVar(&g.debug, "debug", false, "verbose debug logging to stderr")
	fs.BoolVar(&g.noBanner, "no-banner", false, "suppress the banner")

	var fqdnCache, out string
	var all, skipStale bool
	var exclude stringList
	fs.BoolVar(&all, "all", false, "check every policy at once instead of -l pods (-n then only limits which namespace)")
	fs.Var(&exclude, "exclude-policy", "with --all, never put missing rules in this policy unless no other selects the pod: name, namespace/name or clusterwide/name, globs allowed (repeatable)")
	fs.StringVar(&out, "o", "missing-rules.yaml", "file to write the missing rules to (with --all: a directory, default missing-rules)")
	fs.StringVar(&out, "out", "missing-rules.yaml", "file to write the missing rules to (with --all: a directory, default missing-rules)")
	fs.StringVar(&fqdnCache, "fqdn-cache", "", "resolve destinations from this saved *-fqdn dump instead of the live cache")
	fs.BoolVar(&skipStale, "skip-stale-ips", false, "log flows to/from a private IP no running pod or node holds, but write no rule for them (careful: also skips private IPs outside the cluster with no DNS name)")

	fs.Usage = func() {
		printGrouped("verify",
			"Watch live traffic for the selected pods and log every flow the CiliumNetworkPolicy\n"+
				"already deployed for them does NOT allow. The rules that would allow them are\n"+
				"written to -o as they appear. With --all, every policy is checked at once and each\n"+
				"one missing rules gets its own file under -o. Read-only: never touches the cluster.\n"+
				"Runs until you stop it (Ctrl+C).",
			"  cnpgen verify -l app.kubernetes.io/name=my-app -n my-namespace -o missing.yaml\n"+
				"  cnpgen verify --all -o missing-rules/",
			fs, [][2]any{
				{"Target", []string{"l", "n", "all", "exclude-policy"}},
				{"Output", []string{"o"}},
				{"Tuning", []string{"fqdn-cache", "skip-stale-ips"}},
				{"Cluster", []string{"context", "kubeconfig", "cilium-namespace", "cilium-selector", "nodes"}},
				{"Misc", []string{"debug", "no-banner"}},
			})
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	ui.Debug = g.debug
	showBanner(&g)

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if all {
		if g.label != "" {
			return fail("-l and --all can't be combined: --all checks every policy, -l one set of pods")
		}
		if !set["n"] && !set["namespace"] {
			g.namespace = "" // every namespace
		}
		if !set["o"] && !set["out"] {
			out = "missing-rules"
		}
		for _, e := range exclude {
			if err := policyindex.ValidateExclude(e); err != nil {
				return fail("--exclude-policy: %v", err)
			}
		}
	} else if len(exclude) > 0 {
		return fail("--exclude-policy only applies with --all: -l writes every missing rule to one file")
	} else if code, ok := requireTarget(&g, false); !ok {
		return code
	}

	k, err := g.newKube()
	if err != nil {
		return fail("%v", err)
	}

	// Ctrl+C cancels the context; verify stops cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := verifycmd.Run(ctx, k, verifycmd.Config{
		Label:     g.label,
		Namespace: g.namespace,
		All:       all,
		Out:       out,
		FqdnDump:  fqdnCache,
		Exclude:   policyindex.Excludes(exclude),
		SkipStale: skipStale,
	}); err != nil {
		return fail("%v", err)
	}
	return 0
}

func cmdGenerate(argv []string) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	var g globalFlags
	g.register(fs)
	var flows, resolved, fqdnCache string
	var live bool
	fs.StringVar(&flows, "flows", "", "flows file to build from: JSON array or NDJSON (required)")
	fs.StringVar(&resolved, "resolved", "", "resolved index JSON from a prior run")
	fs.StringVar(&fqdnCache, "fqdn-cache", "", "resolve IPs from this saved *-fqdn dump")
	fs.BoolVar(&live, "live", false, "fetch the FQDN cache from the live cluster to resolve IPs")

	fs.Usage = func() {
		printGrouped("generate",
			"Build CiliumNetworkPolicy files offline from a saved flows file, no cluster\n"+
				"access needed. Same policy-building step audit runs each round, as a one-shot.",
			"  cnpgen generate -l app.kubernetes.io/name=my-app -n my-namespace \\\n"+
				"      --flows flows.json --fqdn-cache my-fqdn-dump",
			fs, [][2]any{
				{"Target", []string{"l", "n"}},
				{"Input", []string{"flows", "fqdn-cache", "resolved", "live", "o"}},
				{"Tuning", []string{"allow-domain", "pin-domain", "known-ip", "allow-extra", "accept-suggestions", "seed-policy"}},
				{"Cluster (only with -live)", []string{"context", "kubeconfig", "cilium-namespace", "cilium-selector", "nodes"}},
				{"Misc", []string{"debug", "no-banner"}},
			})
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	ui.Debug = g.debug
	showBanner(&g)

	if code, ok := requireTarget(&g, false); !ok {
		return code
	}
	if flows == "" {
		return fail("pass --flows (the flows file to build from), or use 'cnpgen audit' to collect live traffic")
	}

	cfg := g.newSettings()
	seed, err := g.loadSeed()
	if err != nil {
		return fail("%v", err)
	}
	fmt.Println(ui.Bold("Looking at traffic for " + pipeline.DescribeTarget(g.label, g.namespace) + "."))

	loaded, err := collect.LoadFlowsFile(flows)
	if err != nil {
		return fail("reading --flows %s: %v", flows, err)
	}

	ctx := context.Background()
	var sources []resolve.Source
	if fqdnCache != "" {
		if m, err := resolve.FqdnCacheFromDump(fqdnCache); err == nil {
			sources = append(sources, resolve.Source{Name: "fqdn-cache", Map: m})
		} else {
			ui.Warn("reading --fqdn-cache %s: %v", fqdnCache, err)
		}
	} else if live {
		k, err := g.newKube()
		if err != nil {
			return fail("%v", err)
		}
		if m, err := resolve.FqdnCacheLive(ctx, k); err == nil {
			sources = append(sources, resolve.Source{Name: "fqdn-cache", Map: m})
		} else {
			ui.Warn("fetching live FQDN cache: %v", err)
		}
	}
	sources = append(sources, resolve.Source{Name: "flow-l7", Map: resolve.FqdnFromFlows(loaded)})
	index := resolve.BuildIndex(sources, cfg.KnownIPs)

	policies := pipeline.GeneratePolicies(loaded, g.label, g.namespace, index, cfg, g.accept, false, true, seed)
	paths, err := pipeline.WritePolicies(policies, g.output)
	if err != nil {
		return fail("writing policies: %v", err)
	}
	fmt.Println(ui.Green(fmt.Sprintf("Wrote %d policy file(s)", len(paths))) + " -> " + g.output + "/")
	for _, p := range paths {
		fmt.Println(ui.Dim("  " + p))
	}
	pipeline.PrintNotes(policies)
	return 0
}

// cmdCleanup deletes every cnpgen-managed CiliumNetworkPolicy in a namespace,
// or with -l only the ones an audit run with that same -l deployed.
// It exists for the Helm chart's pre-delete hook: on `helm uninstall`, RBAC
// and the audit Deployment can be torn down before the running pod gets a
// chance to clean up after itself, so the policy it deployed while learning
// would otherwise leak. Running this as its own hook Job, before the chart's
// other resources are removed, closes that race.
//
// --scale-down, if given, first scales that Deployment to 0 and waits for it
// to fully drain, so no in-flight audit round can re-apply a policy between
// this delete and the Deployment actually stopping.
func cmdCleanup(argv []string) int {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	var g globalFlags
	g.register(fs)
	for _, name := range []string{"l", "label"} {
		fs.Lookup(name).Usage = "only delete the policies deployed by `cnpgen audit` with this same -l (repeatable)"
	}
	var scaleDown, scaleDownNamespace string
	fs.StringVar(&scaleDown, "scale-down", "", "scale this Deployment to 0 and wait for it to drain before deleting policies")
	fs.StringVar(&scaleDownNamespace, "scale-down-namespace", "", "namespace of --scale-down (default: -n)")
	fs.Usage = func() {
		printGrouped("cleanup",
			"Delete every cnpgen-managed CiliumNetworkPolicy from a namespace, or with -l only\n"+
				"the ones deployed by `cnpgen audit -l <same label>`. Used by the Helm chart's\n"+
				"pre-delete hook so `helm uninstall` doesn't leave the policy behind.",
			"  cnpgen cleanup -n my-namespace\n  cnpgen cleanup -n my-namespace -l app.kubernetes.io/name=my-app",
			fs, [][2]any{
				{"Target", []string{"l", "n"}},
				{"Drain first", []string{"scale-down", "scale-down-namespace"}},
				{"Cluster", []string{"context", "kubeconfig"}},
				{"Misc", []string{"debug", "no-banner"}},
			})
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	ui.Debug = g.debug
	showBanner(&g)

	if g.namespace == "" {
		return fail("-n <namespace> can't be empty: it's the namespace to remove cnpgen's policies from")
	}

	k, err := g.newKube()
	if err != nil {
		return fail("%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if scaleDown != "" {
		ns := scaleDownNamespace
		if ns == "" {
			ns = g.namespace
		}
		fmt.Println(ui.Dim(fmt.Sprintf("Scaling %s/%s to 0 and waiting for it to drain...", ns, scaleDown)))
		if err := k.ScaleDeploymentToZeroAndWait(ctx, scaleDown, ns); err != nil {
			return fail("scaling down %s/%s: %v", ns, scaleDown, err)
		}
	}

	targets := dedupe(g.labels)
	if len(targets) == 0 {
		targets = []string{""} // every cnpgen-managed policy
	}
	var names []string
	for _, label := range targets {
		n, err := k.ListManagedNames(ctx, g.namespace, generate.ManagedByLabel, generate.ManagedByValue,
			generate.TargetAnnotation, label)
		if err != nil {
			return fail("listing cnpgen-managed policies in %q: %v", g.namespace, err)
		}
		names = append(names, n...)
	}
	if len(names) == 0 {
		fmt.Println(ui.Dim("No cnpgen-managed policies in " + g.namespace + "."))
		return 0
	}
	code := 0
	for _, name := range names {
		r := deploy.DeleteOne(ctx, k, name, g.namespace, name)
		flag := ui.Green("ok")
		if r.Skipped {
			flag = ui.Yellow("skip")
		} else if !r.OK {
			flag = ui.Red("FAIL")
		}
		fmt.Printf("  %s  %s: %s\n", flag, r.Label, r.Msg)
		if !r.OK {
			code = 1
		}
	}
	return code
}

// reviewRow is one pickable line in `cnpgen review`: a wildcard-suggestion
// group found in one file.
type reviewRow struct {
	path   string
	suffix string
	group  review.Group
}

// reviewLabel renders a picker row for a wildcard-suggestion group: the
// wildcard it would become on the main line, and the exact domains it
// replaces underneath, so checking a row visibly means "use the wildcard".
func reviewLabel(g review.Group) (label, sub string) {
	return ui.Bold("*."+g.Suffix) + ui.Dim(" (wildcard)"),
		fmt.Sprintf("instead of %d exact domain(s): %s", len(g.Members), strings.Join(g.Members, ", "))
}

// reviewFiles expands the paths given to `cnpgen review` into the policy
// files to scan: a file is taken as is, a directory contributes its
// *.yaml/*.yml files (not recursively). Sorted, without duplicates.
func reviewFiles(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var files []string
	add := func(path string) {
		path = filepath.Clean(path)
		if !seen[path] {
			seen[path] = true
			files = append(files, path)
		}
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() && (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
				add(filepath.Join(p, name))
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

// cmdReview reads the policy files given as arguments (files, or directories
// whose *.yaml/*.yml files are all taken; netpol-out by default), finds the
// wildcard-suggestion/wildcard-applied marker comments generate left behind,
// and lets the operator check/uncheck which ones should be wildcarded in a
// single picker, then rewrites every changed file in place. It never touches
// the cluster or re-runs the generate pipeline: the next audit round
// regenerates the file from scratch anyway, so there's nothing to persist
// beyond what's already on disk.
func cmdReview(argv []string) int {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	var output string
	var noBanner bool
	// -o/--output is kept for scripts written before review took paths.
	fs.StringVar(&output, "o", "", "directory of policy files to review (same as passing it as an argument)")
	fs.StringVar(&output, "output", "", "directory of policy files to review (same as passing it as an argument)")
	fs.BoolVar(&noBanner, "no-banner", false, "suppress the banner")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Choose which groups of sibling domains to allow through one wildcard\n"+
			"(matchPattern: \"*.suffix\") instead of one matchName per observed domain,\n"+
			"then rewrite the affected policy files in place. Re-run cnpgen\n"+
			"audit/generate afterwards and a decision stays only if the same suggestion\n"+
			"still applies.\n\n"+
			"Usage:\n  cnpgen review [options] [file|dir ...]   (default: netpol-out)\n\n"+
			"Example:\n"+
			"  cnpgen review\n"+
			"  cnpgen review netpol-out/my-app.yaml\n\n"+
			"Misc:\n")
		fmt.Fprintf(os.Stderr, "  %-22s %s\n\n", "-no-banner", fs.Lookup("no-banner").Usage)
	}
	// The flag package stops at the first positional argument: keep parsing
	// after each one so flags may come after the paths too.
	var paths []string
	for {
		if err := fs.Parse(argv); err != nil {
			return 2
		}
		argv = fs.Args()
		if len(argv) == 0 {
			break
		}
		paths = append(paths, argv[0])
		argv = argv[1:]
	}
	if output != "" {
		paths = append(paths, output)
	}
	if len(paths) == 0 {
		paths = []string{"netpol-out"}
	}
	if !noBanner {
		fmt.Fprint(os.Stderr, banner)
	}

	files, err := reviewFiles(paths)
	if err != nil {
		return fail("%v", err)
	}
	where := strings.Join(paths, ", ")
	if len(files) == 0 {
		fmt.Println(ui.Dim("No policy files in " + where + "."))
		return 0
	}

	fileLines := map[string][]string{}
	var rows []reviewRow
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fail("reading %s: %v", path, err)
		}
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		fileLines[path] = lines
		for _, g := range review.Find(lines) {
			rows = append(rows, reviewRow{path: path, suffix: g.Suffix, group: g})
		}
	}
	if len(rows) == 0 {
		fmt.Println(ui.Dim("No wildcard suggestions in " + where + "."))
		return 0
	}

	multiFile := len(files) > 1
	items := make([]ui.PickerItem, len(rows))
	for i, r := range rows {
		label, sub := reviewLabel(r.group)
		if multiFile {
			label = ui.Dim(r.path+": ") + label
		}
		items[i] = ui.PickerItem{Label: label, SubLabel: sub, Checked: r.group.Wildcarded}
	}

	fmt.Println("Checked: allow the group through its " + ui.Bold("*.suffix") + " wildcard (one matchPattern).")
	fmt.Println("Unchecked: keep one exact matchName per observed domain.")
	fmt.Println()
	picked, ok := ui.Picker("Space/Enter to toggle a group, arrows to move, Esc to cancel:", items)
	if !ok {
		fmt.Println(ui.Dim("Cancelled, nothing changed."))
		return 0
	}
	wantChecked := make([]bool, len(rows))
	for _, i := range picked {
		wantChecked[i] = true
	}

	toggleBySuffix := map[string]map[string]bool{} // path -> suffix -> toggle?
	var changes []string
	for i, r := range rows {
		if wantChecked[i] == r.group.Wildcarded {
			continue // no change needed
		}
		if toggleBySuffix[r.path] == nil {
			toggleBySuffix[r.path] = map[string]bool{}
		}
		toggleBySuffix[r.path][r.suffix] = true
		if wantChecked[i] {
			changes = append(changes, fmt.Sprintf("  %s: %s now replaces %d exact domain(s)",
				r.path, ui.Bold("*."+r.suffix), len(r.group.Members)))
		} else {
			changes = append(changes, fmt.Sprintf("  %s: %s back to %d exact domain(s)",
				r.path, ui.Bold("*."+r.suffix), len(r.group.Members)))
		}
	}
	if len(toggleBySuffix) == 0 {
		fmt.Println(ui.Dim("Nothing changed."))
		return 0
	}

	for path, suffixes := range toggleBySuffix {
		out, err := review.ToggleAll(fileLines[path], suffixes)
		if err != nil {
			return fail("%s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
			return fail("writing %s: %v", path, err)
		}
	}
	fmt.Println(ui.Green(fmt.Sprintf("Updated %d group(s) across %d file(s):", len(changes), len(toggleBySuffix))))
	for _, c := range changes {
		fmt.Println(c)
	}
	return 0
}

// requireTarget validates the target flags with a fix-oriented message.
// Returns (exitCode, ok). -l is always required; -n defaults to "default" but
// can't be passed empty.
// multi allows several -l.
func requireTarget(g *globalFlags, multi bool) (int, bool) {
	if g.label == "" {
		return fail("pass -l <label> to pick which pods to watch, e.g. -l app.kubernetes.io/name=my-app"), false
	}
	for _, l := range g.labels {
		if l == "" {
			return fail("-l can't be empty"), false
		}
	}
	if !multi && len(g.labels) > 1 {
		return fail("pass -l only once here (only `cnpgen audit` and `cnpgen cleanup` take several)"), false
	}
	if g.namespace == "" {
		return fail("-n <namespace> can't be empty: it's both which namespace to watch pods in and where the policy is written"), false
	}
	return 0, true
}

// dedupe drops repeated values, keeping the first occurrence's order.
func dedupe(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func seedFlows(ctx context.Context, k *kube.Client, labels []string, flowsFile string, last int) ([]*hubble.Flow, error) {
	if flowsFile != "" {
		f, err := collect.LoadFlowsFile(flowsFile)
		if err != nil {
			return nil, fmt.Errorf("reading --flows %s: %w", flowsFile, err)
		}
		fmt.Println(ui.Dim(fmt.Sprintf("Starting from %d flow(s) in %s (not live traffic).", len(f), flowsFile)))
		return f, nil
	}
	if last == 0 {
		// Hubble's own `--last 0` falls back to its default (20), so passing it
		// through would silently include history. Skip seed collection entirely.
		fmt.Println(ui.Dim("Starting from nothing (--last 0): round 1 only uses live traffic."))
		return nil, nil
	}
	// One batch per label, so each gets the same last N flows as it would
	// audited alone (with all labels in one batch, a busy app would crowd
	// out a quiet one).
	var f []*hubble.Flow
	for _, label := range labels {
		lf, err := collect.CollectLast(ctx, k, label, last, "")
		if err != nil {
			return nil, err
		}
		f = append(f, lf...)
	}
	fmt.Println(ui.Dim(fmt.Sprintf("Starting from the last %d flow(s) already seen "+
		"(may include traffic from before this run, pass --last 0 to skip that).", last)))
	return f, nil
}

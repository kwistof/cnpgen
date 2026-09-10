```
  _________  ____  ____  ___  ____
 / ___/ __ \/ __ \/ __ `/ _ \/ __ \
/ /__/ / / / /_/ / /_/ /  __/ / / /
\___/_/ /_/ .___/\__, /\___/_/ /_/
         /_/    /____/

   Cilium Network Policy Generator
           by kwistof - v0.1.2
```

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey.svg)

cnpgen watches what your pods actually talk to and writes a [Cilium](https://cilium.io/) network policy for them, built from real observed traffic, not guesswork.

It never blocks anything on its own: every policy deploys in non-enforcing mode (`enableDefaultDeny: false`), so it can only *learn* what a policy would allow. Turning enforcement on is the one step it leaves to you.

Single static Go binary, no runtime dependencies: no `kubectl`, `hubble`, or `cilium` CLI needed. Runs from your laptop or as a Deployment on the cluster.

---

## Run it

**From your laptop** against your current kube context:

```bash
go install github.com/kwistof/cnpgen/cmd/cnpgen@latest

cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace
```

**On the cluster** with the [Helm chart](charts/cnpgen): it runs as a Deployment that watches in the background:

```bash
helm install cnpgen oci://ghcr.io/kwistof/charts/cnpgen -n cnpgen --create-namespace \
  --set target.label=app.kubernetes.io/name=my-app \
  --set target.namespace=my-namespace
```

See the [chart README](charts/cnpgen/README.md) for pulling the generated policy out and cleaning up.

Either way, cnpgen watches, writes a policy file, and deploys it safely, refining it each round until you stop it (or it settles). When you're happy with the file, flip `enableDefaultDeny` to `true` and apply: that's enforcement.

---

## Usage

```bash
# The whole tool. Runs until you stop it (Ctrl+C).
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace

# Auto-stop once 3 rounds in a row see no new blocked traffic.
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --settle 3

# Watch longer per round, so rare connections get captured too.
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --duration 600

# Preview only, don't touch the cluster.
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --dry-run
```

- **`-l`**: which pods to watch, by label.
- **`-n`**: which namespace to watch those pods in, and where the generated policy is written/deployed. Defaults to `default`. A `CiliumNetworkPolicy` only ever matches pods in its own namespace, so `-l` and `-n` always apply together.

The policy is deployed only while cnpgen learns; it's removed when the run ends. The generated policy **file** stays in `netpol-out/` for you to review and apply with enforcement.

Build from a saved flows file with no cluster access using `cnpgen generate --flows flows.json`. Tune resolution with `--allow-domain '*.auth0.com'`, `--known-ip IP=DOMAIN`, `--allow-extra CIDR:PORT`. See `cnpgen audit -h` for everything.

### Reviewing wildcard suggestions

When sibling domains share a parent (e.g. `tenant1.auth0.com`, `tenant2.auth0.com`), cnpgen can collapse them into one `*.auth0.com` rule. By default it leaves them as exact domains and comments what it could combine instead; pass `--accept-suggestions` to wildcard them right away.

Decide later, without touching the cluster, with:

```bash
cnpgen review -o netpol-out
```

This opens a checklist of every wildcard-eligible group across your policy files. Check the ones you want as `*.suffix` wildcards, leave the rest as exact domains, and it rewrites the changed files. Since `audit`/`generate` regenerate the file from scratch each run, treat `review` as your last pass before applying enforcement, not a permanent setting.

### Starting from an existing policy

Point `--seed-policy` at an existing `CiliumNetworkPolicy` file (hand-written, or from a previous cnpgen run) to carry its `toFQDNs`/`toCIDR` rules into a new run:

```bash
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --seed-policy old-policy.yaml
```

Every domain and CIDR already in that file is kept in the generated policy from round one, whether or not this run's traffic actually confirms it — a floor, not a starting guess that gets discarded. Real traffic still extends the policy as usual. The seed file's `endpointSelector` must match `-l`, or cnpgen refuses to use it (protects against seeding the wrong app's rules by mistake).

---

## Safety

- **Never enforces on its own.** Policies are additive (`enableDefaultDeny: false`) and can't drop live traffic. Enforcement is a manual edit.
- **Never touches foreign policies.** cnpgen only manages policies it labelled `app.kubernetes.io/managed-by=cnpgen`; anything else is left alone.

---

## License

MIT. See [LICENSE](LICENSE).

---
**Author**: kwistof | **GitHub**: https://github.com/kwistof/cnpgen

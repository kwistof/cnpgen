```
  _________  ____  ____  ___  ____
 / ___/ __ \/ __ \/ __ `/ _ \/ __ \
/ /__/ / / / /_/ / /_/ /  __/ / / /
\___/_/ /_/ .___/\__, /\___/_/ /_/
         /_/    /____/

   Cilium Network Policy Generator
           by kwistof - v0.7.0
```

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey.svg)

cnpgen watches what your pods actually talk to (through Hubble) and writes a [Cilium](https://cilium.io/) network policy from that traffic.

It never blocks anything: policies it deploys are non-enforcing (`enableDefaultDeny: false`). Turning enforcement on is up to you.

Single Go binary. No `kubectl`, `hubble` or `cilium` CLI needed.

---

## Install

```bash
go install github.com/kwistof/cnpgen/cmd/cnpgen@latest
```

Or run it in the cluster with the [Helm chart](charts/cnpgen).

---

## Build a policy: `cnpgen audit`

```bash
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace
```

- `-l`: the pods to watch, by label.
- `-n`: their namespace, where the policy is deployed.

Each round, cnpgen writes the policy to `netpol-out/`, deploys it (non-enforcing), and watches for traffic it still misses. It runs until Ctrl+C. The deployed policy is removed at the end; the file stays.

```bash
# Stop after 3 rounds in a row with nothing missing
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --settle 3

# Watch 10 minutes per round, to catch rare connections
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --duration 600

# Write the file only, don't deploy anything
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --dry-run

# Keep the rules of an existing policy file
cnpgen audit -l app.kubernetes.io/name=my-app -n my-namespace --seed-policy old-policy.yaml
```

When the file looks right, set `enableDefaultDeny` to `true` and apply it.

See `cnpgen audit -h` for all options (`--allow-domain`, `--known-ip`, `--allow-extra`, ...).

### Several apps at once

Repeat `-l`, one per app:

```bash
cnpgen audit -l app.kubernetes.io/name=frontend -l app.kubernetes.io/name=backend -n webshop
```

Each app gets its own policy, exactly as if audited alone (with `--settle`, each stops and is cleaned up on its own), but they all share one `hubble observe` process in every Cilium agent pod, about 15 MB. With the Helm chart, list them in `target.labels`.

You can also run one `cnpgen audit` per app at the same time (separate terminals, or one Helm release each). They can share a namespace and the output directory, but each run adds its own `hubble observe` process in every Cilium agent pod.

---

## Check an existing policy: `cnpgen verify`

```bash
cnpgen verify -l app.kubernetes.io/name=my-app -n my-namespace -o missing.yaml
```

Read-only. It watches the pods against the policy already deployed (any policy, not only cnpgen's), until Ctrl+C:

- every flow the policy blocks, or would block once enforced, is logged:

  ```
  10:43:20  BLOCKED egress   my-app.my-namespace -> api.github.com (140.82.121.6)  443/TCP  [new rule]
  10:43:21  BLOCKED egress   my-app.my-namespace -> api.github.com (140.82.121.6)  443/TCP
  ```

- `missing.yaml` (default `missing-rules.yaml`) holds the rules to add, updated as new ones appear:

  ```yaml
  egress:
  - toFQDNs:
    - matchName: "api.github.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  ```

  Copy each entry into the `egress`/`ingress` list of your policy.

If no policy selects the pods, nothing is blocked, so nothing is reported.
Traffic a rule allowing everything (`toEntities: [all]` with no ports) lets
through isn't reported either.

When running several `verify` at once, give each its own `-o` file.

### Every policy at once: `cnpgen verify --all`

```bash
cnpgen verify --all -o missing-rules/              # every namespace
cnpgen verify --all -n my-namespace -o missing-rules/
```

Same as `verify`, but for every CiliumNetworkPolicy (and
CiliumClusterwideNetworkPolicy) in the cluster, in one process with one
`hubble observe` per Cilium agent, however many policies there are. Each
blocked flow is matched to the policy selecting the pod it's enforced at
(egress at the source, ingress at the destination) and logged with it:

```
10:43:20  BLOCKED egress   [webshop/frontend] frontend.webshop -> example.com (104.20.23.154)  443/TCP  [new rule]
```

and the rules to add go to one file per policy, `missing-rules/<namespace>/<policy>.missing.yaml`
(`_clusterwide/<policy>.missing.yaml` for clusterwide policies). When several
policies select the same pods, the rules go to the cnpgen policy generated for
them if there is one, else the first by name; the file names the others. Pods
blocked without any visible policy selecting them land in
`_unattributed/<namespace>/<app>.missing.yaml`. Files are only written for
policies missing rules, and never deleted: start from an empty `-o` directory.

Only blocked flows leave the Cilium agents (Hubble filters them with
`--cel-expression`). On a Hubble too old for that, cnpgen filters them itself,
which costs it noticeably more CPU on a busy node.

---

## Other commands

```bash
# Build policy files offline from a saved flows file
cnpgen generate -l app.kubernetes.io/name=my-app -n my-namespace --flows flows.json

# Choose which sibling domains to merge into wildcards (e.g. *.auth0.com)
cnpgen review -o netpol-out

# Delete the policies cnpgen deployed in a namespace
cnpgen cleanup -n my-namespace
```

---

## Safety

- **Never enforces.** Enforcement is a manual edit.
- **Never touches other policies.** cnpgen only changes policies labelled `app.kubernetes.io/managed-by=cnpgen`.

---

## License

MIT. See [LICENSE](LICENSE).

---
**Author**: kwistof | **GitHub**: https://github.com/kwistof/cnpgen

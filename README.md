```
  _________  ____  ____  ___  ____
 / ___/ __ \/ __ \/ __ `/ _ \/ __ \
/ /__/ / / / /_/ / /_/ /  __/ / / /
\___/_/ /_/ .___/\__, /\___/_/ /_/
         /_/    /____/

   Cilium Network Policy Generator
           by kwistof - v0.3.0
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

Run one `cnpgen audit` per app, at the same time (separate terminals, or one Helm release each). They can share a namespace and the output directory:

```bash
cnpgen audit -l app.kubernetes.io/name=frontend -n webshop
cnpgen audit -l app.kubernetes.io/name=backend  -n webshop
```

Each run adds one `hubble observe` process in every Cilium agent pod, about 15 MB each.

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

When running several `verify` at once, give each its own `-o` file.

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

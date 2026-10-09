# cnpgen

![Version: 0.7.5](https://img.shields.io/badge/Version-0.7.5-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.7.5](https://img.shields.io/badge/AppVersion-0.7.5-informational?style=flat-square)

Run cnpgen in your cluster to generate a Cilium network policy from observed traffic.

Runs [cnpgen](https://github.com/kwistof/cnpgen) as a `Deployment` in the
cluster, in one of three modes:

- `audit` (default): builds a policy from the traffic it sees and deploys it in
  non-enforcing mode. It never blocks traffic.
- `verify`: read-only. Logs every flow the policy already deployed blocks, and
  writes the rules to add.
- `verify-all`: `verify` for every policy at once, with one file of rules to
  add per policy.

All run until you uninstall.

## Build a policy (audit)

```bash
helm install cnpgen oci://ghcr.io/kwistof/charts/cnpgen -n cnpgen --create-namespace \
  --set target.label=app.kubernetes.io/name=my-app \
  --set target.namespace=my-namespace
```

Follow it:

```bash
kubectl -n cnpgen logs -f deploy/cnpgen
```

Get the policy files:

```bash
POD=$(kubectl -n cnpgen get pod -l app.kubernetes.io/instance=cnpgen -o jsonpath='{.items[0].metadata.name}')
kubectl -n cnpgen cp "$POD":/out ./netpol-out
```

To enforce, set `enableDefaultDeny` to `true` in the file and apply it.

## Check an existing policy (verify)

```bash
helm install cnpgen oci://ghcr.io/kwistof/charts/cnpgen -n cnpgen --create-namespace \
  --set target.label=app.kubernetes.io/name=my-app \
  --set target.namespace=my-namespace \
  --set audit.mode=verify
```

See every blocked flow:

```bash
kubectl -n cnpgen logs -f deploy/cnpgen
```

Get the rules to add to your policy:

```bash
POD=$(kubectl -n cnpgen get pod -l app.kubernetes.io/instance=cnpgen -o jsonpath='{.items[0].metadata.name}')
kubectl -n cnpgen cp "$POD":/out/missing-rules.yaml ./missing-rules.yaml
```

## Check every policy at once (verify-all)

```bash
helm install cnpgen oci://ghcr.io/kwistof/charts/cnpgen -n cnpgen --create-namespace \
  --set audit.mode=verify-all
```

Add `--set target.namespace=my-namespace` to only check the policies of one
namespace. Get the rules to add, one `<namespace>/<policy>.missing.yaml` per
policy:

```bash
POD=$(kubectl -n cnpgen get pod -l app.kubernetes.io/instance=cnpgen -o jsonpath='{.items[0].metadata.name}')
kubectl -n cnpgen cp "$POD":/out ./missing-rules
```

## Uninstall

```bash
helm uninstall cnpgen -n cnpgen
```

In `audit` mode, this also deletes the policy cnpgen deployed. In `verify`
and `verify-all` modes, nothing on the cluster is touched.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Pod affinity. |
| audit.dryRun | bool | `false` | Preview the policy without deploying it. `audit` mode only. |
| audit.duration | int | `120` | Seconds to watch per round. `audit` mode only. |
| audit.extraArgs | list | `[]` | Extra raw args passed to `cnpgen audit`/`cnpgen verify`, e.g. `["--allow-domain", "*.auth0.com"]`. |
| audit.mode | string | `"audit"` | `audit` builds a policy from observed traffic. `verify` is read-only: it logs every flow the policy already deployed in target.namespace blocks, and writes the rules to add to `/out/missing-rules.yaml`. `verify-all` does the same for every policy at once (leave target.label empty), writing one `/out/<namespace>/<policy>.missing.yaml` per policy missing rules. |
| ciliumNamespace | string | `"kube-system"` | Namespace where the Cilium agent pods run, cnpgen execs into them. Since this chart runs `cnpgen audit` as a long-lived Deployment, expect one long-lived `hubble observe --follow` exec session per Cilium agent pod for the lifetime of this release (about 15 MB in each agent pod). To audit several apps at once, list them in target.labels (one stream for all), or install one release per app (one stream each); they can share a namespace. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"ghcr.io/kwistof/cnpgen"` | Image repository. |
| image.tag | string | `""` | Image tag. Defaults to the chart's `appVersion`. |
| nodeSelector | object | `{}` | Pod node selector. |
| rbac.create | bool | `true` | Create the ClusterRole/ClusterRoleBinding (manage CiliumNetworkPolicies) and Role/RoleBinding (exec into Cilium pods). |
| rbac.lookupPodIPs | bool | `true` | With `audit.mode: verify` or `verify-all`, also let cnpgen list pods in every namespace, to say which pod or node holds a blocked peer IP Cilium has no identity for (or that none does: a stale IP). Pod objects include their env values, so turn this off if that access is too broad; cnpgen then logs those peers by IP only. |
| resources | object | `{}` | Pod resource requests/limits. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount for the Job. |
| serviceAccount.name | string | `""` | ServiceAccount name. Empty uses the chart's fullname. |
| target.label | string | `""` | Label selecting which pods to watch, e.g. `app.kubernetes.io/name=my-app`. **Required** (unless `target.labels` is set), except with `audit.mode: verify-all`, where it must be empty. |
| target.labels | list | `[]` | More labels to audit in this same release, on top of `target.label` (`audit` mode only), e.g. `["app.kubernetes.io/name=frontend", "app.kubernetes.io/name=backend"]`. Each gets its own policy, as with one release per label, but they share one `hubble observe` stream per Cilium agent instead of one each. |
| target.namespace | string | `""` | Namespace to watch those pods in, and where the generated CiliumNetworkPolicy is written/deployed (a CNP only ever matches pods in its own namespace). **Required**, except with `audit.mode: verify-all`, where it optionally limits the check to one namespace. |
| tolerations | list | `[]` | Pod tolerations. |

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| kwistof |  | <https://github.com/kwistof> |

## Source Code

* <https://github.com/kwistof/cnpgen>

----------------------------------------------
Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs).

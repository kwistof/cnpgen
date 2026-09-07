// Package kube wraps the Kubernetes client-go library with the handful of
// operations cnpgen needs: discovering Cilium agent pods, exec'ing into them
// (both batch and streaming, e.g. `hubble observe`), and creating/deleting/
// reading CiliumNetworkPolicy CRDs.
//
// This shells out to nothing: no `kubectl` binary is required. A single
// static binary can be dropped onto a pod and run.
package kube

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/kwistof/cnpgen/internal/ui"
)

// ciliumContainer is the container Exec targets inside a Cilium agent pod.
// Cilium's DaemonSet always names it this, upstream and on every distro
// (AKS, EKS, etc.) that ships extra sidecar/init containers alongside it, so
// PodExecOptions must say which one explicitly whenever a pod has more than
// one container.
const ciliumContainer = "cilium-agent"

// cnpGVR is the GroupVersionResource for CiliumNetworkPolicy.
var cnpGVR = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumnetworkpolicies",
}

// Pod is a discovered Cilium agent pod.
type Pod struct {
	Name string
	Node string
}

// Client wraps the typed and dynamic Kubernetes clients plus the REST config
// needed for pod exec.
type Client struct {
	config          *rest.Config
	clientset       *kubernetes.Clientset
	dyn             dynamic.Interface
	ciliumNamespace string
	ciliumSelector  string
	nodes           map[string]struct{} // nil = all nodes
}

// Options configures a Client.
type Options struct {
	Context         string
	Kubeconfig      string
	CiliumNamespace string
	CiliumSelector  string
	Nodes           []string
}

// New builds a Client. It uses in-cluster config when running inside a pod and
// no kubeconfig is given, otherwise the usual kubeconfig resolution.
func New(opts Options) (*Client, error) {
	config, err := restConfig(opts.Context, opts.Kubeconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("building clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	var nodes map[string]struct{}
	if len(opts.Nodes) > 0 {
		nodes = map[string]struct{}{}
		for _, n := range opts.Nodes {
			nodes[n] = struct{}{}
		}
	}
	ns := opts.CiliumNamespace
	if ns == "" {
		ns = "kube-system"
	}
	sel := opts.CiliumSelector
	if sel == "" {
		sel = "k8s-app=cilium"
	}
	return &Client{
		config:          config,
		clientset:       clientset,
		dyn:             dyn,
		ciliumNamespace: ns,
		ciliumSelector:  sel,
		nodes:           nodes,
	}, nil
}

func restConfig(kubeContext, kubeconfig string) (*rest.Config, error) {
	// In-cluster first when nothing else is specified: this is the "run it on
	// a pod" path.
	if kubeconfig == "" && kubeContext == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	} else if env := os.Getenv("KUBECONFIG"); env == "" {
		if home, err := os.UserHomeDir(); err == nil {
			rules.Precedence = append(rules.Precedence, filepath.Join(home, ".kube", "config"))
		}
	}
	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	return cfg, nil
}

// ScaleDeploymentToZeroAndWait scales a Deployment to 0 replicas and blocks
// until the API server reports it fully drained (status.replicas == 0), or
// ctx is done. A missing Deployment is not an error: there's nothing to
// drain. Used by the pre-delete cleanup hook so no in-flight audit round can
// re-apply a policy after it's been deleted.
func (c *Client) ScaleDeploymentToZeroAndWait(ctx context.Context, name, namespace string) error {
	deployments := c.clientset.AppsV1().Deployments(namespace)
	dep, err := deployments.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting deployment %s/%s: %w", namespace, name, err)
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 {
		zero := int32(0)
		dep.Spec.Replicas = &zero
		if _, err := deployments.Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("scaling %s/%s to 0: %w", namespace, name, err)
		}
	}
	for {
		dep, err := deployments.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("polling deployment %s/%s: %w", namespace, name, err)
		}
		if dep.Status.Replicas == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// CountPodsMatching returns how many pods match label in namespace. Used for
// an upfront sanity check: if it's 0, -l/-n almost certainly don't point at
// anything real yet.
func (c *Client) CountPodsMatching(ctx context.Context, label, namespace string) (int, error) {
	list, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		return 0, fmt.Errorf("listing pods matching %q in %q: %w", label, namespace, err)
	}
	return len(list.Items), nil
}

// CiliumPods returns the Cilium agent pods, filtered by the node set if given.
func (c *Client) CiliumPods(ctx context.Context) ([]Pod, error) {
	list, err := c.clientset.CoreV1().Pods(c.ciliumNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: c.ciliumSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing cilium pods: %w", err)
	}
	var pods []Pod
	for _, p := range list.Items {
		node := p.Spec.NodeName
		if c.nodes != nil {
			if _, ok := c.nodes[node]; !ok {
				continue
			}
		}
		pods = append(pods, Pod{Name: p.Name, Node: node})
	}
	ui.Log("Selected %d cilium pod(s)", len(pods))
	return pods, nil
}

// Exec runs argv in a Cilium pod and returns combined stdout / stderr.
func (c *Client) Exec(ctx context.Context, pod string, argv []string) (stdout, stderr string, err error) {
	var out, errBuf bytes.Buffer
	err = c.stream(ctx, pod, argv, nil, &out, &errBuf)
	return out.String(), errBuf.String(), err
}

// ExecStream runs argv in a Cilium pod, writing stdout to w as it arrives.
// Cancel ctx to stop it. Used for `hubble observe --follow`.
func (c *Client) ExecStream(ctx context.Context, pod string, argv []string, w io.Writer) error {
	return c.stream(ctx, pod, argv, nil, w, io.Discard)
}

func (c *Client) stream(ctx context.Context, pod string, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(c.ciliumNamespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: ciliumContainer,
			Command:   argv,
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("exec setup for %s: %w", pod, err)
	}
	ui.Log("exec in %s: %v", pod, argv)
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})
	// A cancelled context is the normal way we stop a --follow stream; don't
	// surface it as an error.
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

// Ownership is the result of checking who a CiliumNetworkPolicy on the
// cluster belongs to.
type Ownership int

const (
	// OwnershipMissing means no object of that name/namespace exists.
	OwnershipMissing Ownership = iota
	// OwnershipOurs means it carries cnpgen's managed-by label.
	OwnershipOurs
	// OwnershipForeign means it exists without that label: created by
	// something else (hand-written, another tool, or pre-existing).
	OwnershipForeign
)

// ListManagedNames returns the names of every CiliumNetworkPolicy in
// namespace carrying cnpgen's managed-by label.
func (c *Client) ListManagedNames(ctx context.Context, namespace, managedByLabel, managedByValue string) ([]string, error) {
	list, err := c.dyn.Resource(cnpGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: managedByLabel + "=" + managedByValue,
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.GetName())
	}
	return names, nil
}

// ApplyManaged creates or updates a CiliumNetworkPolicy, but only ever
// touches one cnpgen itself created. The ownership check and the write share
// a single Get, and the write carries that Get's exact resourceVersion as a
// precondition, so there is no gap between "check the label" and "act" for
// something else to create, replace, or relabel the object in: the server
// rejects the write with a conflict rather than cnpgen silently overwriting
// (and thereby adopting) a policy it didn't create.
func (c *Client) ApplyManaged(ctx context.Context, obj map[string]any, managedByLabel, managedByValue string) (Ownership, error) {
	u := &unstructured.Unstructured{Object: obj}
	ns := u.GetNamespace()
	res := c.dyn.Resource(cnpGVR).Namespace(ns)

	existing, err := res.Get(ctx, u.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = res.Create(ctx, u, metav1.CreateOptions{})
		return OwnershipMissing, err
	}
	if err != nil {
		return OwnershipMissing, err
	}
	if existing.GetLabels()[managedByLabel] != managedByValue {
		return OwnershipForeign, nil
	}
	u.SetResourceVersion(existing.GetResourceVersion())
	u.SetUID(existing.GetUID())
	_, err = res.Update(ctx, u, metav1.UpdateOptions{})
	return OwnershipOurs, err
}

// DeleteManaged deletes a CiliumNetworkPolicy by name/namespace, but only
// ever one cnpgen itself created. Like ApplyManaged, the ownership check and
// the delete share a single Get, and the delete carries that Get's exact UID
// as a precondition, so the server refuses the delete (rather than silently
// removing something else) if the object was replaced in between.
func (c *Client) DeleteManaged(ctx context.Context, name, namespace, managedByLabel, managedByValue string) (Ownership, error) {
	res := c.dyn.Resource(cnpGVR).Namespace(namespace)
	existing, err := res.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return OwnershipMissing, nil
	}
	if err != nil {
		return OwnershipMissing, err
	}
	if existing.GetLabels()[managedByLabel] != managedByValue {
		return OwnershipForeign, nil
	}
	uid := existing.GetUID()
	err = res.Delete(ctx, name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return OwnershipOurs, err
	}
	return OwnershipOurs, nil
}

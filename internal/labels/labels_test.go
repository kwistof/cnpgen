package labels

import (
	"reflect"
	"testing"
)

func TestGetApp(t *testing.T) {
	cases := []struct {
		labels []string
		want   string
	}{
		{[]string{"k8s:app.kubernetes.io/name=hybris-front"}, "k8s:app.kubernetes.io/name=hybris-front"},
		{[]string{"k8s:app=foo"}, "k8s:app=foo"},
		{[]string{"reserved:world"}, "reserved:world"},
		{[]string{"reserved:host"}, "reserved:host"},
		{[]string{"k8s:io.kubernetes.pod.namespace=x"}, ""},
		// Priority follows appLabelKeys, not the order of the labels.
		{[]string{"k8s:app=foo", "k8s:app.kubernetes.io/name=bar"}, "k8s:app.kubernetes.io/name=bar"},
		{[]string{"k8s:io.cilium.k8s.policy.serviceaccount=sa", "k8s:k8s-app=foo"}, "k8s:k8s-app=foo"},
		// No app label: fall back to the service account, except "default".
		{[]string{
			"k8s:control-plane=solr-operator",
			"k8s:io.cilium.k8s.policy.serviceaccount=solrcloud-solr-operator",
			"k8s:io.kubernetes.pod.namespace=solr-operator",
		}, "k8s:io.cilium.k8s.policy.serviceaccount=solrcloud-solr-operator"},
		{[]string{"k8s:control-plane=x", "k8s:io.cilium.k8s.policy.serviceaccount=default"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := GetApp(c.labels); got != c.want {
			t.Errorf("GetApp(%v) = %q, want %q", c.labels, got, c.want)
		}
	}
}

func TestGetPeerApp(t *testing.T) {
	controlPlane := []string{"reserved:kube-apiserver", "reserved:remote-node"}
	cases := []struct {
		labels []string
		port   int32
		want   string
	}{
		{[]string{"reserved:remote-node"}, 4318, "reserved:remote-node"},
		{[]string{"reserved:kube-apiserver"}, 4318, "reserved:kube-apiserver"},
		// A node running the API server: named by the port.
		{controlPlane, 6443, "reserved:kube-apiserver"},
		{controlPlane, 443, "reserved:kube-apiserver"},
		{controlPlane, 4318, "reserved:remote-node"},
		{[]string{"reserved:host", "reserved:kube-apiserver"}, 10250, "reserved:host"},
		// Dual-stack world is still world.
		{[]string{"reserved:world-ipv4"}, 443, "reserved:world"},
		{[]string{"reserved:world-ipv6"}, 443, "reserved:world"},
	}
	for _, c := range cases {
		if got := GetPeerApp(c.labels, c.port); got != c.want {
			t.Errorf("GetPeerApp(%v, %d) = %q, want %q", c.labels, c.port, got, c.want)
		}
	}
}

func TestEntity(t *testing.T) {
	cases := map[string]string{
		"reserved:host":           "host",
		"reserved:remote-node":    "remote-node",
		"reserved:kube-apiserver": "kube-apiserver",
		"reserved:unknown":        "",
		"reserved:world":          "",
		"k8s:app=foo":             "",
	}
	for app, want := range cases {
		got, ok := Entity(app)
		if got != want || ok != (want != "") {
			t.Errorf("Entity(%q) = %q, %v, want %q", app, got, ok, want)
		}
	}
}

func TestGetNamespace(t *testing.T) {
	if got := GetNamespace([]string{"k8s:io.kubernetes.pod.namespace=webshop"}); got != "webshop" {
		t.Errorf("got %q", got)
	}
	if got := GetNamespace([]string{"k8s:app=foo"}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestAppToLabelSelector(t *testing.T) {
	got := AppToLabelSelector("k8s:app.kubernetes.io/name=foo")
	want := map[string]string{"app.kubernetes.io/name": "foo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if AppToLabelSelector("reserved:world") != nil {
		t.Error("reserved identity should have nil selector")
	}
}

func TestAppToPolicyName(t *testing.T) {
	if got := AppToPolicyName("k8s:app.kubernetes.io/name=hybris-front"); got != "hybris-front" {
		t.Errorf("got %q", got)
	}
	if got := AppToPolicyName("k8s:io.cilium.k8s.policy.serviceaccount=solrcloud-solr-operator"); got != "solrcloud-solr-operator" {
		t.Errorf("got %q", got)
	}
	if got := AppToPolicyName("reserved:world"); got != "reserved-world" {
		t.Errorf("got %q", got)
	}
}

func TestFallbackSelector(t *testing.T) {
	cases := []struct {
		labels []string
		ns     string
		want   string
	}{
		// Own labels win, sorted; generated and Cilium/Kubernetes ones are skipped.
		{[]string{
			"k8s:pod-template-hash=abc",
			"k8s:tier=web",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:control-plane=solr",
			"k8s:io.kubernetes.pod.namespace=x",
		}, "x", "k8s:control-plane=solr"},
		// Nothing usable: the namespace.
		{[]string{"k8s:controller-revision-hash=1", "k8s:io.kubernetes.pod.namespace=x"}, "x", "k8s:io.kubernetes.pod.namespace=x"},
		// Non-k8s sources are not pod labels.
		{[]string{"cidr:10.0.0.0/8"}, "", ""},
	}
	for _, c := range cases {
		if got := FallbackSelector(c.labels, c.ns); got != c.want {
			t.Errorf("FallbackSelector(%v, %q) = %q, want %q", c.labels, c.ns, got, c.want)
		}
	}
}

func TestLabelToApp(t *testing.T) {
	for in, want := range map[string]string{
		"app.kubernetes.io/instance=adm-slowquery-1": "k8s:app.kubernetes.io/instance=adm-slowquery-1",
		"k8s:app=foo": "k8s:app=foo",
		" app = foo ": "k8s:app=foo",
		"app":         "",
		"app=":        "",
	} {
		if got := LabelToApp(in); got != want {
			t.Errorf("LabelToApp(%q) = %q, want %q", in, got, want)
		}
	}
}

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
		{nil, ""},
	}
	for _, c := range cases {
		if got := GetApp(c.labels); got != c.want {
			t.Errorf("GetApp(%v) = %q, want %q", c.labels, got, c.want)
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
	if got := AppToPolicyName("reserved:world"); got != "reserved-world" {
		t.Errorf("got %q", got)
	}
}

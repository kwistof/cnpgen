package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAgentRunning(t *testing.T) {
	status := func(name string, st corev1.ContainerState) corev1.PodStatus {
		return corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: name, State: st}}}
	}
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	waiting := corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}
	now := metav1.Now()

	cases := []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"running", corev1.Pod{Status: status(ciliumContainer, running)}, true},
		{"waiting", corev1.Pod{Status: status(ciliumContainer, waiting)}, false},
		{"no statuses yet", corev1.Pod{}, false},
		{"only another container running", corev1.Pod{Status: status("other", running)}, false},
		{"not ready (node unreachable)", corev1.Pod{Status: func() corev1.PodStatus {
			st := status(ciliumContainer, running)
			st.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
			return st
		}()}, false},
		{"terminating", corev1.Pod{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Status: status(ciliumContainer, running)}, false},
	}
	for _, c := range cases {
		if got := agentRunning(&c.pod); got != c.want {
			t.Errorf("%s: agentRunning = %v, want %v", c.name, got, c.want)
		}
	}
}

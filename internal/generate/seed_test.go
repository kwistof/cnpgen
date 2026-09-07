package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleCNP = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: hybris-back
  namespace: webshop
spec:
  endpointSelector:
    matchLabels:
      app.kubernetes.io/name: hybris-back
  egress:
    - toFQDNs:
        - matchName: seeded.example.com
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    - toCIDR:
        - 10.0.0.5/32
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
`

func writeTempCNP(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSeedMatchingLabel(t *testing.T) {
	path := writeTempCNP(t, sampleCNP)
	seed, err := LoadSeed(path, "app.kubernetes.io/name=hybris-back")
	if err != nil {
		t.Fatal(err)
	}
	key := portProto{Port: 443, Proto: "TCP"}
	if _, ok := seed.fqdnsByPort[key]["seeded.example.com"]; !ok {
		t.Errorf("expected seeded.example.com under port 443/TCP, got %v", seed.fqdnsByPort[key])
	}
	cidrKey := portProto{Port: 8080, Proto: "TCP"}
	if _, ok := seed.cidrByPort[cidrKey]["10.0.0.5/32"]; !ok {
		t.Errorf("expected 10.0.0.5/32 under port 8080/TCP, got %v", seed.cidrByPort[cidrKey])
	}
}

func TestLoadSeedLabelMismatch(t *testing.T) {
	path := writeTempCNP(t, sampleCNP)
	_, err := LoadSeed(path, "app.kubernetes.io/name=frontend")
	if err == nil {
		t.Fatal("expected an error for a mismatched label")
	}
	if !strings.Contains(err.Error(), "frontend") {
		t.Errorf("expected the error to mention the mismatch, got: %v", err)
	}
}

func TestSeedMergeIntoIsAFloor(t *testing.T) {
	path := writeTempCNP(t, sampleCNP)
	seed, err := LoadSeed(path, "app.kubernetes.io/name=hybris-back")
	if err != nil {
		t.Fatal(err)
	}

	fqdnsByPort := map[portProto]map[string]struct{}{}
	cidrByPort := map[portProto]map[string]string{}
	seed.mergeInto(fqdnsByPort, cidrByPort)

	key := portProto{Port: 443, Proto: "TCP"}
	if _, ok := fqdnsByPort[key]["seeded.example.com"]; !ok {
		t.Errorf("expected the seeded domain even with zero observed traffic, got %v", fqdnsByPort)
	}
}

func TestSeedMergeIntoDoesNotOverwriteObserved(t *testing.T) {
	path := writeTempCNP(t, sampleCNP)
	seed, err := LoadSeed(path, "app.kubernetes.io/name=hybris-back")
	if err != nil {
		t.Fatal(err)
	}

	cidrKey := portProto{Port: 8080, Proto: "TCP"}
	cidrByPort := map[portProto]map[string]string{
		cidrKey: {"10.0.0.5/32": "already commented by this round"},
	}
	seed.mergeInto(map[portProto]map[string]struct{}{}, cidrByPort)

	if got := cidrByPort[cidrKey]["10.0.0.5/32"]; got != "already commented by this round" {
		t.Errorf("expected the observed comment to win over the seed's empty one, got %q", got)
	}
}

func TestLoadSeedMissingFile(t *testing.T) {
	if _, err := LoadSeed("/nonexistent/path.yaml", "app.kubernetes.io/name=x"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

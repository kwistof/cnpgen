package settings

import "testing"

func TestParseCIDRPort(t *testing.T) {
	cases := []struct {
		in    string
		cidr  string
		port  int32
		proto string
		cmt   string
		ok    bool
	}{
		{"10.0.5.0/24", "10.0.5.0/24", 0, "", "", true},
		{"10.0.5.0/24:5432", "10.0.5.0/24", 5432, "TCP", "", true},
		{"10.0.5.0/24:53/udp", "10.0.5.0/24", 53, "UDP", "", true},
		{"1.2.3.4:80 # a note", "1.2.3.4", 80, "TCP", "a note", true},
	}
	for _, c := range cases {
		e, ok := ParseCIDRPort(c.in)
		if ok != c.ok {
			t.Errorf("%q: ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if e.CIDR != c.cidr || e.Port != c.port || e.Protocol != c.proto || e.Comment != c.cmt {
			t.Errorf("%q: got %+v", c.in, e)
		}
	}
}

func TestNewKnownIPs(t *testing.T) {
	s := New(nil, nil, []string{"1.2.3.4=api.example.com", "bad-entry"}, nil)
	if s.KnownIPs["1.2.3.4"] != "api.example.com" {
		t.Errorf("known IP not parsed: %v", s.KnownIPs)
	}
	if len(s.KnownIPs) != 1 {
		t.Errorf("bad entry should be dropped: %v", s.KnownIPs)
	}
}

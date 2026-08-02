package version

import "testing"

func TestBuildCompatibilityMetadata(t *testing.T) {
	for name, value := range map[string]string{
		"server":  ServerVersion,
		"minimum": MinimumClientVersion,
		"latest":  LatestClientVersion,
		"frpc":    MinimumFRPCVersion,
	} {
		if _, err := ParseSemVer(value); err != nil {
			t.Fatalf("%s build metadata %q is not SemVer: %v", name, value, err)
		}
	}
	if !IsAtLeast(LatestClientVersion, MinimumClientVersion) {
		t.Fatalf("latest client version %q is below minimum %q", LatestClientVersion, MinimumClientVersion)
	}
}

func TestParseSemVerAndCompare(t *testing.T) {
	parsed, err := ParseSemVer("1.2.3")
	if err != nil || parsed != (SemVer{Major: 1, Minor: 2, Patch: 3}) {
		t.Fatalf("ParseSemVer() = %#v, %v", parsed, err)
	}
	if Compare(parsed, SemVer{Major: 1, Minor: 2, Patch: 2}) <= 0 {
		t.Fatal("newer patch version was not greater")
	}
	if Compare(parsed, parsed) != 0 {
		t.Fatal("equal versions did not compare equally")
	}
	for _, value := range []string{"", "1", "1.2", "1.02.3", "1.2.3-beta", "1.2.x"} {
		if _, err := ParseSemVer(value); err == nil {
			t.Fatalf("invalid version %q was accepted", value)
		}
	}
}

func TestIsAtLeast(t *testing.T) {
	for _, test := range []struct {
		actual  string
		minimum string
		want    bool
	}{
		{actual: "0.1.0", minimum: "0.1.0", want: true},
		{actual: "0.2.0", minimum: "0.1.0", want: true},
		{actual: "0.0.9", minimum: "0.1.0", want: false},
		{actual: "unknown", minimum: "0.1.0", want: false},
	} {
		if got := IsAtLeast(test.actual, test.minimum); got != test.want {
			t.Fatalf("IsAtLeast(%q, %q) = %t, want %t", test.actual, test.minimum, got, test.want)
		}
	}
}

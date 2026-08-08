package version

import "testing"

func TestBuildCompatibilityMetadata(t *testing.T) {
	if _, err := ParseSemVer(ClientVersion); err != nil {
		t.Fatalf("client build metadata %q is not SemVer: %v", ClientVersion, err)
	}
}

func TestVersionComparison(t *testing.T) {
	parsed, err := ParseSemVer("1.2.3")
	if err != nil || parsed != (SemVer{Major: 1, Minor: 2, Patch: 3}) {
		t.Fatalf("ParseSemVer() = %#v, %v", parsed, err)
	}
	if CompareVersionStrings("1.2.4", "1.2.3") <= 0 || CompareVersionStrings("1.2.3", "1.2.3") != 0 || CompareVersionStrings("1.2.2", "1.2.3") >= 0 {
		t.Fatal("version string comparison is incorrect")
	}
	for _, value := range []string{"", "1", "1.2", "1.02.3", "1.2.3-beta", "1.2.x"} {
		if _, err := ParseSemVer(value); err == nil {
			t.Fatalf("invalid version %q was accepted", value)
		}
	}
}

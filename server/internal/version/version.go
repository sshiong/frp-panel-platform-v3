package version

import (
	"fmt"
	"strconv"
	"strings"
)

// These string variables keep development defaults in source while allowing
// the release build to inject independent Server/Client compatibility values
// with Go's -ldflags -X mechanism. Protocol and schema versions stay fixed
// until the API/configuration compatibility policy explicitly changes them.
var (
	ServerVersion        = "0.1.0"
	MinimumClientVersion = "0.1.0"
	LatestClientVersion  = "0.1.0"
	MinimumFRPCVersion   = "0.68.0"
)

const (
	ProtocolVersion     = "v1"
	ConfigSchemaVersion = "v1"
)

// SemVer is the stable three-component version form used by the panel
// compatibility contract. Pre-release builds are deliberately rejected at
// the API boundary so that an unverified build cannot silently pass a minimum
// version gate.
type SemVer struct {
	Major int
	Minor int
	Patch int
}

func ParseSemVer(value string) (SemVer, error) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 3 {
		return SemVer{}, fmt.Errorf("version must have major.minor.patch form")
	}
	parsed := [3]int{}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return SemVer{}, fmt.Errorf("version component is not canonical")
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return SemVer{}, fmt.Errorf("version component is not numeric")
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			return SemVer{}, fmt.Errorf("version component is out of range: %w", err)
		}
		parsed[index] = value
	}
	return SemVer{Major: parsed[0], Minor: parsed[1], Patch: parsed[2]}, nil
}

func Compare(left, right SemVer) int {
	for _, pair := range [][2]int{{left.Major, right.Major}, {left.Minor, right.Minor}, {left.Patch, right.Patch}} {
		if pair[0] > pair[1] {
			return 1
		}
		if pair[0] < pair[1] {
			return -1
		}
	}
	return 0
}

func IsAtLeast(actual, minimum string) bool {
	actualVersion, actualErr := ParseSemVer(actual)
	minimumVersion, minimumErr := ParseSemVer(minimum)
	return actualErr == nil && minimumErr == nil && Compare(actualVersion, minimumVersion) >= 0
}

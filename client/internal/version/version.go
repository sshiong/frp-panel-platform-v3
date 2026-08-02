package version

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	ClientVersion       = "0.1.0"
	ProtocolVersion     = "v1"
	ConfigSchemaVersion = "v1"
)

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

func CompareVersionStrings(left, right string) int {
	leftVersion, leftErr := ParseSemVer(left)
	rightVersion, rightErr := ParseSemVer(right)
	if leftErr != nil || rightErr != nil {
		return 0
	}
	return Compare(leftVersion, rightVersion)
}

func IsAtLeast(actual, minimum string) bool {
	actualVersion, actualErr := ParseSemVer(actual)
	minimumVersion, minimumErr := ParseSemVer(minimum)
	return actualErr == nil && minimumErr == nil && Compare(actualVersion, minimumVersion) >= 0
}

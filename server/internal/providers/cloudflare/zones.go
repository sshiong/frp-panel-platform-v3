package cloudflare

import (
	"sort"
	"strings"
)

// MatchZone returns the most specific accessible Cloudflare zone for a
// normalized hostname. A zone is valid only when it is the hostname itself or
// a complete DNS-label suffix; partial suffixes are rejected.
func MatchZone(hostname string, zones []Zone) (Zone, bool) {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	eligible := make([]Zone, 0, len(zones))
	for _, zone := range zones {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone.Name)), ".")
		if name == "" || (hostname != name && !strings.HasSuffix(hostname, "."+name)) {
			continue
		}
		zone.Name = name
		eligible = append(eligible, zone)
	}
	if len(eligible) == 0 {
		return Zone{}, false
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		return strings.Count(eligible[i].Name, ".") > strings.Count(eligible[j].Name, ".")
	})
	return eligible[0], true
}

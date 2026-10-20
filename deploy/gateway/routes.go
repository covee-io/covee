package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
)

// maxRoutes bounds the routes file; the console offers far fewer.
const maxRoutes = 1024

// The network's own address ranges, which a gateway must never offer.
var networkRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

// readRoutes reads the routes file the management service writes:
//
//	{"routes": ["10.0.0.0/8", "168.63.129.16/32", "203.0.113.7/32"]}
//
// A missing file means no routes. Every entry must be a canonical prefix; an
// internet-wide route (exit node) or one inside the network's own ranges is
// refused, so a damaged file cannot redirect members' traffic.
func readRoutes(path string) ([]netip.Prefix, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("the routes file is too large")
	}
	var file struct {
		Routes []string `json:"routes"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("the routes file is not valid JSON: %w", err)
	}
	if len(file.Routes) > maxRoutes {
		return nil, fmt.Errorf("the routes file lists %d routes; at most %d are allowed", len(file.Routes), maxRoutes)
	}
	out := make([]netip.Prefix, 0, len(file.Routes))
	for _, text := range file.Routes {
		p, err := netip.ParsePrefix(text)
		if err != nil || p != p.Masked() {
			return nil, fmt.Errorf("%q is not an address range such as 10.0.0.0/8", text)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("%q would send all internet traffic through the gateway", text)
		}
		for _, own := range networkRanges {
			if own.Overlaps(p) {
				return nil, fmt.Errorf("%q overlaps the network's own addresses", text)
			}
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out), nil
}

func samePrefixes(a, b []netip.Prefix) bool {
	return slices.Equal(sorted(a), sorted(b))
}

func sorted(in []netip.Prefix) []netip.Prefix {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

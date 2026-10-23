// STATUS: DIAMANT VGT SUPREME
package main

import (
	"net"
	"strings"
)

// Server origin for the live map.
//
// The map shows attacks arriving from somewhere and landing on this host. Naming the
// host's own position turns a scatter of markers into a direction, and it is what makes
// the connection arcs meaningful.
//
// Two honest constraints shape this:
//
//  1. A private address cannot be geolocated. The bundled database contains public
//     address space only, and the resolver refuses anything else - so a server behind
//     NAT with no public address has no derivable position. Inventing one would place
//     the origin marker somewhere on earth the machine is not, and every arc would then
//     point at the wrong place. The result therefore distinguishes "resolved" from
//     "address known but not geolocatable" from "no address at all".
//
//  2. The address chosen must be the one that actually faces the traffic. A host with a
//     management interface and a public interface has two, and picking the wrong one
//     puts the origin in the wrong country. Public global unicast is preferred for that
//     reason; loopback and link-local are never candidates.

// KineticOrigin is the host's own position on the map.
type KineticOrigin struct {
	IP          string  `json:"ip,omitempty"`
	Known       bool    `json:"known"`
	Latitude    float64 `json:"lat,omitempty"`
	Longitude   float64 `json:"lon,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
	Reason      string  `json:"reason,omitempty"`
}

// resolveKineticOrigin determines the host position from its own interfaces.
func (s *APIServer) resolveKineticOrigin() KineticOrigin {
	addresses := localGlobalAddresses()
	if len(addresses) == 0 {
		return KineticOrigin{Reason: "no globally scoped unicast address is configured on this host"}
	}
	if s.geo == nil {
		return KineticOrigin{IP: addresses[0].String(), Reason: "the local GeoIP/ASN database is not available"}
	}

	// Prefer an address the database can actually place. The list is already ordered
	// with public addresses first, so the first successful lookup is the best available
	// answer rather than an arbitrary one.
	for _, address := range addresses {
		record, ok := s.geo.Lookup(address)
		if !ok {
			continue
		}
		return KineticOrigin{
			IP: address.String(), Known: true,
			Latitude: record.Latitude, Longitude: record.Longitude,
			Country: record.Country, CountryCode: record.CountryCode,
			ASN: record.ASN, ASName: record.ASName,
		}
	}

	primary := addresses[0].String()
	if isPrivateAddress(addresses[0]) {
		return KineticOrigin{
			IP:     primary,
			Reason: "this host has only private addresses, and a private address has no entry in a public GeoIP database; set the origin manually if the map should place it",
		}
	}
	return KineticOrigin{
		IP:     primary,
		Reason: "the configured local GeoIP/ASN database contains no entry for this host's own address",
	}
}

// localGlobalAddresses returns the host's globally scoped unicast addresses, public
// ones first and each family internally ordered by interface index so the result is
// stable across calls.
func localGlobalAddresses() []net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	public := make([]net.IP, 0, 4)
	private := make([]net.IP, 0, 4)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if !ip.IsGlobalUnicast() {
				continue
			}
			if isPrivateAddress(ip) {
				private = append(private, ip)
				continue
			}
			public = append(public, ip)
		}
	}
	return append(public, private...)
}

// isPrivateAddress reports whether an address is in private or carrier-grade NAT
// space. It shares the classification the forensics redaction uses, so the two cannot
// disagree about what "internal" means.
func isPrivateAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return true
	}
	// Link-local is internal in the sense that matters here: it is never routable and
	// can never appear in a public GeoIP database. Leaving it out would make the two
	// callers of this predicate disagree about 169.254.0.0/16.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return inCarrierGradeNAT(ip)
}

// describeOrigin renders the origin as one operator sentence, used by the map note so
// the interface never states a position it does not have.
func describeOrigin(origin KineticOrigin) string {
	if origin.Known {
		label := strings.TrimSpace(origin.Country)
		if label == "" {
			label = strings.TrimSpace(origin.CountryCode)
		}
		if label == "" {
			return "origin resolved from this host's own address"
		}
		return "origin resolved from this host's own address: " + label
	}
	if origin.Reason != "" {
		return origin.Reason
	}
	return "origin not resolved"
}

# GeDefense Kinetic Defense – Local GeoIP/ASN Enrichment

GeDefense performs Kinetic map enrichment **locally**. The live security path does not send observed source IP addresses to a third-party geolocation API.

## CSV contract

Configure `kinetic.geoip_csv` to a regular, non-symlink file using the following header/order:

```text
network,country_code,country_name,latitude,longitude,asn,as_name
8.8.8.0/24,US,United States,37.751,-97.822,AS15169,Google LLC
```

Required fields are `network`, two-letter `country_code`, `country_name`, `latitude`, and `longitude`. `asn` and `as_name` are optional. Prefixes are normalized before insertion and longest-prefix matching is used for lookup.

## Security and resource bounds

- Maximum file size: 128 MiB.
- Maximum parsed prefixes: 1,000,000.
- Input must be a regular file and may not be a symlink.
- Latitude/longitude and metadata lengths are validated before publication.
- Parsed tables are built off to the side and published only after the entire file validates.
- Lookup cache is fixed at 4,096 entries and includes negative public-address misses.
- Cache entries are tied to the loaded database generation so a reload cannot make stale cached data authoritative.
- Successful reload clears the bounded cache.
- Private, loopback, link-local, multicast, unspecified and other special-use/documentation ranges (including CGNAT and RFC 5737/RFC 3849 examples) are never geolocated. GeDefense prefers `unknown` over a false geographic pin.

## Operator semantics

GeoIP is contextual evidence, not identity. Country/ASN information is approximate network-origin metadata and must not be treated as proof of a person's physical location.

The Kinetic world map is deliberately bounded:

- the API returns at most 250 live source rows;
- the browser renders at most 96 individual live source pulses;
- country heat is rendered from at most 64 aggregates;
- all time filtering remains server authoritative.

`source_modified_at` exposes the filesystem modification time of the loaded dataset so the dashboard can show data age. `loaded_at` represents when GeDefense successfully validated and published that dataset.

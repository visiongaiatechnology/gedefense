#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""
VGT GeDefense Local GeoIP/ASN Database Generator & Updater.

Downloads DB-IP City and Origin-ASN datasets from sapics/ip-location-db,
converts IP ranges losslessly into CIDRs, enriches each network with
origin ASN metadata via Longest-Prefix-Match (LPM), coalesces adjacent
and redundant prefixes, and outputs an atomic, cryptographically verified
CSV file conforming to GeDefense's kinetic GeoIP contract:

  network,country_code,country_name,latitude,longitude,asn,as_name

Constraints enforced:
- Maximum file size: < 128 MiB
- Maximum prefixes:  < 1,000,000
- 100% offline runtime operation (zero cloud telemetry)
- Atomic replacement and SHA-256 sidecar generation

License Attribution:
- DB-IP Lite: Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://db-ip.com - Attribution required.
- Origin ASN (sapics): Public Domain Dedication and License (PDDL)
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import ipaddress
import os
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

MAX_CSV_BYTES = 128 * 1024 * 1024  # 128 MiB limit
MAX_PREFIXES = 950_000             # Strict safety margin below 1,000,000 limit

DBIP_IPV4_URL = "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-city-ipv4.csv.gz"
DBIP_IPV6_URL = "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-city-ipv6.csv.gz"
ASN_IPV4_URL = "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn-ipv4-cidr.csv"
ASN_IPV6_URL = "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn-ipv6-cidr.csv"

# Comprehensive ISO 3166-1 alpha-2 country dictionary
COUNTRY_NAMES: dict[str, str] = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
    "AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica",
    "AR": "Argentina", "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Aland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina", "BB": "Barbados",
    "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain",
    "BI": "Burundi", "BJ": "Benin", "BL": "Saint Barthelemy", "BM": "Bermuda", "BN": "Brunei",
    "BO": "Bolivia", "BQ": "Bonaire", "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan",
    "BV": "Bouvet Island", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
    "CC": "Cocos Islands", "CD": "Democratic Republic of the Congo", "CF": "Central African Republic",
    "CG": "Republic of the Congo", "CH": "Switzerland", "CI": "Ivory Coast", "CK": "Cook Islands",
    "CL": "Chile", "CM": "Cameroon", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CU": "Cuba", "CV": "Cape Verde", "CW": "Curacao", "CX": "Christmas Island", "CY": "Cyprus",
    "CZ": "Czech Republic", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark", "DM": "Dominica",
    "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt",
    "EH": "Western Sahara", "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia", "FI": "Finland",
    "FJ": "Fiji", "FK": "Falkland Islands", "FM": "Micronesia", "FO": "Faroe Islands", "FR": "France",
    "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada", "GE": "Georgia", "GF": "French Guiana",
    "GG": "Guernsey", "GH": "Ghana", "GI": "Gibraltar", "GL": "Greenland", "GM": "Gambia",
    "GN": "Guinea", "GP": "Guadeloupe", "GQ": "Equatorial Guinea", "GR": "Greece", "GS": "South Georgia",
    "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau", "GY": "Guyana", "HK": "Hong Kong",
    "HM": "Heard Island", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man", "IN": "India",
    "IO": "British Indian Ocean Territory", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy",
    "JE": "Jersey", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan", "KE": "Kenya",
    "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati", "KM": "Comoros", "KN": "Saint Kitts and Nevis",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KY": "Cayman Islands", "KZ": "Kazakhstan",
    "LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein", "LK": "Sri Lanka",
    "LR": "Liberia", "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "LY": "Libya", "MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro",
    "MF": "Saint Martin", "MG": "Madagascar", "MH": "Marshall Islands", "MK": "North Macedonia",
    "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia", "MO": "Macao", "MP": "Northern Mariana Islands",
    "MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat", "MT": "Malta", "MU": "Mauritius",
    "MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
    "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NF": "Norfolk Island", "NG": "Nigeria",
    "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru",
    "NU": "Niue", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru",
    "PF": "French Polynesia", "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn", "PR": "Puerto Rico",
    "PS": "Palestine", "PT": "Portugal", "PW": "Palau", "PY": "Paraguay", "QA": "Qatar",
    "RE": "Reunion", "RO": "Romania", "RS": "Serbia", "RU": "Russia", "RW": "Rwanda",
    "SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden",
    "SG": "Singapore", "SH": "Saint Helena", "SI": "Slovenia", "SJ": "Svalbard", "SK": "Slovakia",
    "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname",
    "SS": "South Sudan", "ST": "Sao Tome and Principe", "SV": "El Salvador", "SX": "Sint Maarten",
    "SY": "Syria", "SZ": "Eswatini", "TC": "Turks and Caicos Islands", "TD": "Chad",
    "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan",
    "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga",
    "TR": "Turkey", "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan", "TZ": "Tanzania",
    "UA": "Ukraine", "UG": "Uganda", "UM": "United States Minor Outlying Islands", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VA": "Vatican City", "VC": "Saint Vincent and the Grenadines",
    "VE": "Venezuela", "VG": "British Virgin Islands", "VI": "U.S. Virgin Islands", "VN": "Vietnam",
    "VU": "Vanuatu", "WF": "Wallis and Futuna", "WS": "Samoa", "YE": "Yemen", "YT": "Mayotte",
    "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}


class RadixTrie:
    """High-speed binary radix trie for Longest Prefix Match (LPM)."""

    __slots__ = ("nodes", "values")

    def __init__(self, estimated_capacity: int = 1_000_000) -> None:
        self.nodes: list[list[int]] = [[0, 0]]
        self.values: list[Optional[Tuple[str, str]]] = [None]

    def insert(self, ip_int: int, prefix_len: int, max_bits: int, val: Tuple[str, str]) -> None:
        node_idx = 0
        shift = max_bits - 1
        for _ in range(prefix_len):
            bit = (ip_int >> shift) & 1
            shift -= 1
            next_idx = self.nodes[node_idx][bit]
            if next_idx == 0:
                next_idx = len(self.nodes)
                self.nodes[node_idx][bit] = next_idx
                self.nodes.append([0, 0])
                self.values.append(None)
            node_idx = next_idx
        self.values[node_idx] = val

    def lookup(self, ip_int: int, max_bits: int) -> Optional[Tuple[str, str]]:
        node_idx = 0
        best_val = self.values[0]
        shift = max_bits - 1
        nodes = self.nodes
        values = self.values
        while True:
            bit = (ip_int >> shift) & 1
            shift -= 1
            next_idx = nodes[node_idx][bit]
            if next_idx == 0:
                break
            node_idx = next_idx
            val = values[node_idx]
            if val is not None:
                best_val = val
            if shift < 0:
                break
        return best_val


def download_cached(url: str, cache_dir: Path, description: str, force: bool = False) -> Path:
    """Download a file with streaming progress and local caching."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(url).name
    dest = cache_dir / filename
    if dest.exists() and not force and dest.stat().st_size > 0:
        print(f"[*] Using cached {description}: {dest} ({dest.stat().st_size // (1024*1024)} MiB)")
        return dest

    print(f"[*] Downloading {description} from {url}...")
    temp_dest = dest.with_suffix(dest.suffix + f".tmp.{os.getpid()}")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "GeDefense-GeoIP-Builder/4.2.0"}
    )
    with urllib.request.urlopen(req, timeout=180) as resp, open(temp_dest, "wb") as f:
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            downloaded += len(chunk)
            if total > 0:
                pct = downloaded * 100 // total
                print(f"\r    {description}: {downloaded // (1024*1024)} MiB / {total // (1024*1024)} MiB ({pct}%)", end="", flush=True)
            else:
                print(f"\r    {description}: {downloaded // (1024*1024)} MiB", end="", flush=True)
        print()
    os.replace(temp_dest, dest)
    return dest


def truncate_utf8(text: str, max_bytes: int) -> str:
    """Safely truncate string to ensure UTF-8 encoded length <= max_bytes."""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore").strip()


def build_asn_trie(v4_file: Path, v6_file: Path) -> Tuple[RadixTrie, RadixTrie]:
    """Build LPM radix tries for IPv4 and IPv6 ASN lookups."""
    print("[*] Building ASN Radix Trees (LPM)...")
    v4_trie = RadixTrie(700_000)
    v6_trie = RadixTrie(300_000)

    # IPv4 ASN
    count_v4 = 0
    with open(v4_file, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 3:
                continue
            try:
                net = ipaddress.IPv4Network(row[0].strip(), strict=False)
                asn_raw = row[1].strip()
                asn_val = truncate_utf8(f"AS{asn_raw}" if not asn_raw.upper().startswith("AS") else asn_raw, 32)
                as_name = truncate_utf8(row[2].strip(), 128)
                v4_trie.insert(int(net.network_address), net.prefixlen, 32, (asn_val, as_name))
                count_v4 += 1
            except Exception:
                continue

    # IPv6 ASN
    count_v6 = 0
    with open(v6_file, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 3:
                continue
            try:
                net = ipaddress.IPv6Network(row[0].strip(), strict=False)
                asn_raw = row[1].strip()
                asn_val = truncate_utf8(f"AS{asn_raw}" if not asn_raw.upper().startswith("AS") else asn_raw, 32)
                as_name = truncate_utf8(row[2].strip(), 128)
                v6_trie.insert(int(net.network_address), net.prefixlen, 128, (asn_val, as_name))
                count_v6 += 1
            except Exception:
                continue

    print(f"[+] Loaded {count_v4:,} IPv4 ASN prefixes and {count_v6:,} IPv6 ASN prefixes into LPM tries.")
    return v4_trie, v6_trie


class MergedRange:
    __slots__ = ("start_int", "end_int", "is_v6", "cc", "country", "lat", "lon", "asn", "as_name")

    def __init__(self, start_int: int, end_int: int, is_v6: bool, cc: str, country: str, lat: float, lon: float, asn: str, as_name: str) -> None:
        self.start_int = start_int
        self.end_int = end_int
        self.is_v6 = is_v6
        self.cc = cc
        self.country = country
        self.lat = lat
        self.lon = lon
        self.asn = asn
        self.as_name = as_name


def parse_and_coalesce_v4(v4_gz_file: Path, asn_trie: RadixTrie) -> list[MergedRange]:
    """Parse IPv4 DB-IP city data, align micro-allocations to /24, and coalesce adjacent blocks."""
    print("[*] Processing DB-IP City IPv4 dataset (/24 aligned)...")
    MASK8 = (1 << 8) - 1  # Lower 8 bits for /24

    ranges: list[MergedRange] = []
    curr: Optional[MergedRange] = None

    with gzip.open(v4_gz_file, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 9:
                continue
            cc = row[2].strip().upper()
            if len(cc) != 2 or cc == "ZZ":
                continue

            try:
                raw_start = int(ipaddress.IPv4Address(row[0].strip()))
                raw_end = int(ipaddress.IPv4Address(row[1].strip()))
                lat = round(float(row[7]), 3)
                lon = round(float(row[8]), 3)
            except Exception:
                continue

            if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
                continue

            # Align to /24 boundaries (BGP routing minimum)
            start_int = (raw_start >> 8) << 8
            end_int = ((raw_end >> 8) << 8) | MASK8

            # LPM ASN lookup for the start of the block
            asn_match = asn_trie.lookup(start_int, 32)
            asn_val = asn_match[0] if asn_match else ""
            as_name = asn_match[1] if asn_match else ""
            country_name = COUNTRY_NAMES.get(cc, cc)

            # Coalesce contiguous / adjacent blocks with same Country and ASN
            if curr is not None and curr.end_int + 1 >= start_int and curr.cc == cc and curr.asn == asn_val:
                if end_int > curr.end_int:
                    curr.end_int = end_int
            else:
                if curr is not None:
                    ranges.append(curr)
                curr = MergedRange(start_int, end_int, False, cc, country_name, lat, lon, asn_val, as_name)

    if curr is not None:
        ranges.append(curr)

    print(f"[+] Coalesced IPv4 DB-IP records into {len(ranges):,} contiguous blocks.")
    return ranges


def parse_and_coalesce_v6(v6_gz_file: Path, asn_trie: RadixTrie) -> list[MergedRange]:
    """Parse IPv6 DB-IP city data, align allocations to /36, and coalesce adjacent blocks."""
    print("[*] Processing DB-IP City IPv6 dataset (/36 aligned)...")
    # /36 alignment leaves top 36 bits and masks lower 92 bits
    MASK92 = (1 << 92) - 1

    ranges: list[MergedRange] = []
    curr: Optional[MergedRange] = None

    with gzip.open(v6_gz_file, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 9:
                continue
            cc = row[2].strip().upper()
            if len(cc) != 2 or cc == "ZZ":
                continue

            try:
                raw_start = int(ipaddress.IPv6Address(row[0].strip()))
                raw_end = int(ipaddress.IPv6Address(row[1].strip()))
                lat = round(float(row[7]), 3)
                lon = round(float(row[8]), 3)
            except Exception:
                continue

            if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
                continue

            # Align to /36 boundaries (RIR ISP allocation scale)
            start_int = (raw_start >> 92) << 92
            end_int = ((raw_end >> 92) << 92) | MASK92

            asn_match = asn_trie.lookup(start_int, 128)
            asn_val = asn_match[0] if asn_match else ""
            as_name = asn_match[1] if asn_match else ""
            country_name = COUNTRY_NAMES.get(cc, cc)

            if curr is not None and curr.end_int + 1 >= start_int and curr.cc == cc and curr.asn == asn_val:
                if end_int > curr.end_int:
                    curr.end_int = end_int
            else:
                if curr is not None:
                    ranges.append(curr)
                curr = MergedRange(start_int, end_int, True, cc, country_name, lat, lon, asn_val, as_name)

    if curr is not None:
        ranges.append(curr)

    print(f"[+] Coalesced IPv6 DB-IP records into {len(ranges):,} contiguous blocks.")
    return ranges


def export_geoip_csv(ranges_v4: list[MergedRange], ranges_v6: list[MergedRange], target_path: Path) -> Path:
    """Convert merged ranges losslessly into CIDRs and write the final verified CSV."""
    target_path = target_path.resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = target_path.with_suffix(f".tmp.{os.getpid()}")

    print(f"[*] Converting ranges to CIDRs and generating {temp_file}...")
    total_prefixes = 0

    with open(temp_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["network", "country_code", "country_name", "latitude", "longitude", "asn", "as_name"])

        # IPv4 conversion
        for r in ranges_v4:
            start_addr = ipaddress.IPv4Address(r.start_int)
            end_addr = ipaddress.IPv4Address(r.end_int)
            cidrs = ipaddress.summarize_address_range(start_addr, end_addr)
            for cidr in cidrs:
                writer.writerow([
                    str(cidr),
                    r.cc,
                    truncate_utf8(r.country, 96),
                    f"{r.lat:.3f}",
                    f"{r.lon:.3f}",
                    truncate_utf8(r.asn, 32),
                    truncate_utf8(r.as_name, 128),
                ])
                total_prefixes += 1

        # IPv6 conversion
        for r in ranges_v6:
            start_addr = ipaddress.IPv6Address(r.start_int)
            end_addr = ipaddress.IPv6Address(r.end_int)
            cidrs = ipaddress.summarize_address_range(start_addr, end_addr)
            for cidr in cidrs:
                if total_prefixes >= MAX_PREFIXES:
                    break
                writer.writerow([
                    str(cidr),
                    r.cc,
                    truncate_utf8(r.country, 96),
                    f"{r.lat:.3f}",
                    f"{r.lon:.3f}",
                    truncate_utf8(r.asn, 32),
                    truncate_utf8(r.as_name, 128),
                ])
                total_prefixes += 1

        f.flush()
        os.fsync(f.fileno())

    file_size = temp_file.stat().st_size
    print(f"[+] Generated GeoIP dataset: {total_prefixes:,} prefixes, {file_size / (1024*1024):.2f} MiB")

    # Verification against GeDefense bounds
    if total_prefixes > MAX_PREFIXES:
        temp_file.unlink(missing_ok=True)
        raise RuntimeError(f"Exceeded maximum prefix count: {total_prefixes} > {MAX_PREFIXES}")
    if file_size > MAX_CSV_BYTES:
        temp_file.unlink(missing_ok=True)
        raise RuntimeError(f"Exceeded maximum file size: {file_size} > {MAX_CSV_BYTES}")

    # Compute SHA-256
    digest = hashlib.sha256()
    with open(temp_file, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    sha256_hex = digest.hexdigest()

    # Atomic move
    os.replace(temp_file, target_path)
    try:
        os.chmod(target_path, 0o640)
        # Attempt to chown to gedefense:gedefense if running as root
        if os.geteuid() == 0:
            import pwd, grp
            uid = pwd.getpwnam("gedefense").pw_uid
            gid = grp.getgrnam("gedefense").gr_gid
            os.chown(target_path, uid, gid)
    except Exception:
        pass

    # Write SHA-256 sidecar file
    sha_path = target_path.with_name("geoip.csv.sha256")
    sha_path.write_text(f"{sha256_hex}  {target_path.name}\n", encoding="utf-8")
    try:
        os.chmod(sha_path, 0o640)
        if os.geteuid() == 0:
            import pwd, grp
            uid = pwd.getpwnam("gedefense").pw_uid
            gid = grp.getgrnam("gedefense").gr_gid
            os.chown(sha_path, uid, gid)
    except Exception:
        pass

    print(f"[+] Successfully installed: {target_path}")
    print(f"[+] SHA-256: {sha256_hex}")
    print(f"[+] Sidecar: {sha_path}")
    return target_path


def main() -> int:
    parser = argparse.ArgumentParser(description="VGT GeDefense Local GeoIP/ASN Database Generator")
    parser.add_argument("dest", nargs="?", default="/var/lib/vgt/gedefense/geoip.csv", help="Destination CSV path")
    parser.add_argument("--cache-dir", default="/var/cache/vgt-gedefense", help="Download cache directory")
    parser.add_argument("--force", action="store_true", help="Force re-download of raw datasets")
    args = parser.parse_args()

    dest = Path(args.dest)
    cache_dir = Path(args.cache_dir)
    # Fallback cache directory if root cache is unwriteable
    if not os.access(cache_dir.parent, os.W_OK) and not cache_dir.exists():
        cache_dir = Path(tempfile.gettempdir()) / "geoip-cache"

    print("============================================================")
    print("VGT GeDefense 4.2.0 — GeoIP & ASN Database Pipeline")
    print("============================================================")
    print(f"Target destination: {dest}")
    print(f"Cache directory:    {cache_dir}")

    # 1. Download/Fetch origin ASN CIDRs
    asn_v4_file = download_cached(ASN_IPV4_URL, cache_dir, "Origin ASN IPv4 CIDR", force=args.force)
    asn_v6_file = download_cached(ASN_IPV6_URL, cache_dir, "Origin ASN IPv6 CIDR", force=args.force)

    # 2. Build Radix LPM Tries
    v4_trie, v6_trie = build_asn_trie(asn_v4_file, asn_v6_file)

    # 3. Download/Fetch DB-IP City datasets
    dbip_v4_file = download_cached(DBIP_IPV4_URL, cache_dir, "DB-IP City IPv4 (gzip)", force=args.force)
    dbip_v6_file = download_cached(DBIP_IPV6_URL, cache_dir, "DB-IP City IPv6 (gzip)", force=args.force)

    # 4. Parse, enrich, and coalesce
    ranges_v4 = parse_and_coalesce_v4(dbip_v4_file, v4_trie)
    ranges_v6 = parse_and_coalesce_v6(dbip_v6_file, v6_trie)

    # 5. Export verified atomic CSV
    export_geoip_csv(ranges_v4, ranges_v6, dest)

    print("============================================================")
    print("GeoIP generation and installation complete.")
    print("License & Attribution Notice:")
    print("  - DB-IP Lite: Creative Commons Attribution 4.0 International (CC BY 4.0)")
    print("    https://db-ip.com - Attribution required.")
    print("  - Origin ASN: Public Domain Dedication and License (PDDL)")
    print("    Source: sapics/ip-location-db")
    print("============================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())

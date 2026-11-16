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
- Downloads and staging use only private 0700 directories with unpredictable
  names (no predictable /tmp cache path, no /tmp fallback)
- The canonical ``geoip.csv.sha256`` sidecar is JSON that binds the dataset by
  SHA-256, and the optional ``geoip.csv.sig`` is a Base64 Ed25519 signature over
  the exact canonical sidecar bytes. Both hash and signature are verified in the
  private staging directory BEFORE any file is replaced (FIND-006); a failed
  verification leaves the installed dataset untouched.
- Atomic replacement, then SHA-256 sidecar installation

License Attribution:
- DB-IP Lite: Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://db-ip.com - Attribution required.
- Origin ASN (sapics): Public Domain Dedication and License (PDDL)
"""

from __future__ import annotations

import argparse
import base64
import re
import csv
import gzip
import hashlib
import io
import ipaddress
import os
import shutil
import stat
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

MAX_CSV_BYTES = 128 * 1024 * 1024  # 128 MiB limit
MAX_PREFIXES = 950_000             # Strict safety margin below 1,000,000 limit

# Canonical signed sidecar contract shared with control/geoip.go
# (parseGeoIPIntegritySidecar / verifyGeoIPCIntegrity):
#   geoip.csv.sha256 -> canonical JSON, sorted keys, compact ASCII:
#       {"file":"geoip.csv","schema":"vgt.gedefense.geoip-integrity.v1",
#        "sha256":"<64 lowercase hex>","size":<int>}
#   geoip.csv.sig    -> Base64 (standard alphabet) Ed25519 signature over the
#                       exact bytes of geoip.csv.sha256.
# The same bytes are re-canonicalised in Go and compared exactly, so the
# producer/consumer contract is byte-for-byte, not a loose JSON dialect.
GEOIP_INTEGRITY_SCHEMA = "vgt.gedefense.geoip-integrity.v1"
DEFAULT_CACHE_DIR = "/var/cache/vgt-gedefense"
MAX_SIGNATURE_BYTES = 1024

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


def _release_security():
    """Import the shared release-security primitives (canonical JSON, Ed25519)."""
    scripts = str(Path(__file__).resolve().parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import vgt_release_security  # noqa: PLC0415

    return vgt_release_security


def ensure_private_directory(path: Path) -> Path:
    """Create/return a directory that is not a symlink and is only owner-accessible.

    The download cache and the staging directory carry untrusted external bytes,
    so they must never be world/group writable and must never be a symlink an
    unprivileged user could have planted.
    """
    path = Path(path).expanduser()
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink as private directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"private directory is not a directory: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        try:
            os.chmod(path, 0o700)
        except OSError as error:
            raise RuntimeError(f"private directory is group/other accessible and cannot be tightened: {path}") from error
    return path


def resolve_cache_dir(explicit: str) -> Path:
    """Resolve the download cache directory and fail closed without a fallback.

    An unwritable system cache is a configuration error, not a reason to fall
    back to a predictable path under /tmp: the previous ``/tmp/geoip-cache``
    fallback let an unprivileged user plant the raw datasets.
    """
    if explicit:
        return ensure_private_directory(Path(explicit))
    try:
        return ensure_private_directory(Path(DEFAULT_CACHE_DIR))
    except (OSError, RuntimeError) as error:
        raise RuntimeError(
            f"download cache directory {DEFAULT_CACHE_DIR} is not usable ({error}); "
            "pass --cache-dir with a private 0700 directory instead of relying on a /tmp fallback"
        ) from error


def _checked_cached_file(cache_dir: Path, dest: Path) -> Optional[Path]:
    """Return an existing cache entry only when it is a regular non-symlink file."""
    try:
        info = os.lstat(dest)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"cache entry is not a regular non-symlink file: {dest}")
    if info.st_size <= 0:
        raise RuntimeError(f"cache entry is empty: {dest}")
    return dest


def download_cached(url: str, cache_dir: Path, description: str, force: bool = False) -> Path:
    """Download a file into the private cache with an unpredictable temp name."""
    cache_dir = ensure_private_directory(cache_dir)
    filename = Path(url).name
    dest = cache_dir / filename
    if not force and dest.exists():
        cached = _checked_cached_file(cache_dir, dest)
        if cached is not None:
            print(f"[*] Using cached {description}: {cached} ({cached.stat().st_size // (1024*1024)} MiB)")
            return cached

    print(f"[*] Downloading {description} from {url}...")
    if not url.startswith("https://"):
        raise RuntimeError(f"refusing non-HTTPS download: {url}")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "GeDefense-GeoIP-Builder/6.0.1"}
    )
    # mkstemp creates an unpredictable 0600 file inside the private cache dir; a
    # predictable .tmp.<pid> name in a shared directory was attacker-writable.
    fd, temporary_name = tempfile.mkstemp(prefix=filename + ".", suffix=".part", dir=str(cache_dir))
    temporary = Path(temporary_name)
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            final_url = resp.geturl() if hasattr(resp, "geturl") else url
            if not str(final_url).startswith("https://"):
                raise RuntimeError(f"download redirected outside HTTPS: {final_url}")
            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with os.fdopen(fd, "wb") as handle:
                fd = -1  # ownership transferred to the file object
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = downloaded * 100 // total
                        print(f"\r    {description}: {downloaded // (1024*1024)} MiB / {total // (1024*1024)} MiB ({pct}%)", end="", flush=True)
                    else:
                        print(f"\r    {description}: {downloaded // (1024*1024)} MiB", end="", flush=True)
                handle.flush()
                os.fsync(handle.fileno())
            print()
        if downloaded <= 0:
            raise RuntimeError(f"downloaded zero bytes for {description}")
        os.chmod(temporary, 0o600)
        if dest.is_symlink():
            raise RuntimeError(f"refusing symlink cache destination: {dest}")
        os.replace(temporary, dest)
        return dest
    finally:
        if fd != -1:
            os.close(fd)
        temporary.unlink(missing_ok=True)


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


@dataclass
class StagedGeoIPDataset:
    """Generated dataset plus canonical sidecars in a private 0700 staging directory.

    Nothing here is installed. ``commit_staged_dataset`` is the only function
    that replaces installed files, and it must only be reached after
    ``authenticate_staged_dataset`` verified digest and signature (FIND-006).
    """

    directory: Path
    target_path: Path
    csv_path: Path
    sidecar_path: Path
    sha256: str
    size: int
    signature_path: Optional[Path] = None

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_integrity_sidecar(csv_name: str, sha256_hex: str, size: int) -> bytes:
    """Return the canonical JSON sidecar shared with control/geoip.go.

    The exact bytes produced here are what the Go loader re-canonicalises and
    compares byte-for-byte, and what the Ed25519 signature in geoip.csv.sig
    covers. Keys are sorted (file, schema, sha256, size), the JSON is compact
    ASCII and there is no trailing newline.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", sha256_hex):
        raise RuntimeError("integrity sidecar SHA-256 must be 64 lowercase hex characters")
    document = {
        "file": csv_name,
        "schema": GEOIP_INTEGRITY_SCHEMA,
        "sha256": sha256_hex,
        "size": int(size),
    }
    return _release_security().canonical_json_bytes(document)


def write_geoip_csv(ranges_v4: list[MergedRange], ranges_v6: list[MergedRange], csv_path: Path) -> tuple[int, int]:
    """Convert merged ranges losslessly into CIDRs and write the dataset CSV.

    Returns ``(prefix_count, file_size)``. Resource bounds are enforced before
    the caller can hash, sign or install the file.
    """
    total_prefixes = 0
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["network", "country_code", "country_name", "latitude", "longitude", "asn", "as_name"])

        # IPv4 conversion
        for r in ranges_v4:
            start_addr = ipaddress.IPv4Address(r.start_int)
            end_addr = ipaddress.IPv4Address(r.end_int)
            for cidr in ipaddress.summarize_address_range(start_addr, end_addr):
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

        # IPv6 conversion (bounded by the same total prefix budget)
        for r in ranges_v6:
            if total_prefixes >= MAX_PREFIXES:
                break
            start_addr = ipaddress.IPv6Address(r.start_int)
            end_addr = ipaddress.IPv6Address(r.end_int)
            for cidr in ipaddress.summarize_address_range(start_addr, end_addr):
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

    file_size = csv_path.stat().st_size
    if total_prefixes > MAX_PREFIXES:
        raise RuntimeError(f"Exceeded maximum prefix count: {total_prefixes} > {MAX_PREFIXES}")
    if file_size > MAX_CSV_BYTES:
        raise RuntimeError(f"Exceeded maximum file size: {file_size} > {MAX_CSV_BYTES}")
    return total_prefixes, file_size


def stage_geoip_dataset(ranges_v4: list[MergedRange], ranges_v6: list[MergedRange], target_path: Path) -> StagedGeoIPDataset:
    """Write dataset + canonical sidecar into an unpredictable private 0700 directory.

    The staging directory lives next to the target so the later atomic replace
    stays on one filesystem, but its name is random and its mode is 0700. The
    installed dataset is never touched from this function.
    """
    target_path = Path(target_path).expanduser()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=".vgt-geoip-staging-", dir=str(target_path.parent)))
    os.chmod(directory, 0o700)  # mkdtemp already returns 0700; make the contract explicit
    try:
        if stat.S_IMODE(os.lstat(directory).st_mode) & 0o077:
            raise RuntimeError("staging directory is not private (mode must be 0700)")
        csv_path = directory / target_path.name
        print(f"[*] Converting ranges to CIDRs in private staging: {csv_path}")
        total_prefixes, file_size = write_geoip_csv(ranges_v4, ranges_v6, csv_path)
        sha256_hex = _sha256_file(csv_path)
        print(f"[+] Staged GeoIP dataset: {total_prefixes:,} prefixes, {file_size / (1024*1024):.2f} MiB")
        sidecar_path = directory / (target_path.name + ".sha256")
        with open(sidecar_path, "wb") as handle:
            handle.write(canonical_integrity_sidecar(target_path.name, sha256_hex, file_size))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(csv_path, 0o600)
        os.chmod(sidecar_path, 0o600)
        print(f"[+] Canonical SHA-256 sidecar staged: {sidecar_path}")
        return StagedGeoIPDataset(
            directory=directory,
            target_path=target_path,
            csv_path=csv_path,
            sidecar_path=sidecar_path,
            sha256=sha256_hex,
            size=file_size,
        )
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def _decode_base64_signature(raw: bytes) -> bytes:
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("geoip.csv.sig is not ASCII Base64") from error
    security = _release_security()
    try:
        signature = base64.b64decode(text, validate=True)
    except (base64.binascii.Error, ValueError) as error:  # type: ignore[attr-defined]
        try:
            signature = base64.b64decode(text + "=" * ((4 - len(text) % 4) % 4), validate=True)
        except (base64.binascii.Error, ValueError):
            raise RuntimeError(f"geoip.csv.sig is not valid Base64: {error}") from error
    if len(signature) != security.ED25519_SIGNATURE_SIZE:
        raise RuntimeError("geoip.csv.sig does not contain a 64-byte Ed25519 signature")
    return signature


def _write_staged_signature(staged: StagedGeoIPDataset, signature: bytes) -> None:
    security = _release_security()
    if len(signature) != security.ED25519_SIGNATURE_SIZE:
        raise RuntimeError("refusing to stage a malformed Ed25519 signature")
    signature_path = staged.directory / (staged.target_path.name + ".sig")
    encoded = base64.b64encode(signature).decode("ascii") + "\n"
    with open(signature_path, "wb") as handle:
        handle.write(encoded.encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(signature_path, 0o600)
    staged.signature_path = signature_path


def authenticate_staged_dataset(
    staged: StagedGeoIPDataset,
    *,
    expected_sha256: str = "",
    signature_path: Optional[Path] = None,
    verify_key_path: Optional[Path] = None,
    signing_key_path: Optional[Path] = None,
) -> None:
    """Authenticate the staged dataset before any installed file is replaced.

    This is the producer-side trust decision: the operator-pinned SHA-256 and/or
    the Base64 Ed25519 signature over the canonical sidecar JSON must cover the
    exact staged bytes. ``--signing-key`` may additionally sign the canonical
    sidecar for mirror publication (geoip.csv.sig). Any failure here aborts the
    update without a partial replacement.
    """
    security = _release_security()
    actual = _sha256_file(staged.csv_path)
    if actual != staged.sha256:
        raise RuntimeError("staged GeoIP dataset changed after hashing; refusing to install")
    if staged.csv_path.stat().st_size != staged.size:
        raise RuntimeError("staged GeoIP dataset size changed after staging; refusing to install")
    sidecar_bytes = staged.sidecar_path.read_bytes()
    if sidecar_bytes != canonical_integrity_sidecar(staged.target_path.name, staged.sha256, staged.size):
        raise RuntimeError("staged integrity sidecar is not the canonical JSON document")
    if staged.sidecar_path.name != staged.target_path.name + ".sha256":
        raise RuntimeError("staged integrity sidecar has an unexpected name")

    if expected_sha256:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise RuntimeError("--expected-sha256 is not a SHA-256 value")
        if actual != expected_sha256.lower():
            raise RuntimeError("generated geoip.csv does not match the pinned --expected-sha256")
        print("[+] Staged dataset matches the pinned --expected-sha256")

    if (signature_path is None) != (verify_key_path is None):
        raise RuntimeError("--signature and --verify-key must be provided together")
    if signature_path is not None and verify_key_path is not None:
        public = security.load_release_public_key(verify_key_path)
        raw_signature = security.read_limited(signature_path, limit=MAX_SIGNATURE_BYTES)
        signature = _decode_base64_signature(raw_signature)
        if not security.ed25519_verify(public, sidecar_bytes, signature):
            raise RuntimeError(
                "geoip.csv.sig Ed25519 signature over the canonical sidecar JSON failed verification "
                "(the signed sidecar must bind this dataset's SHA-256 and size)"
            )
        _write_staged_signature(staged, signature)
        print("[+] Staged dataset signature verified against the pinned mirror key (Base64 over canonical sidecar JSON)")

    if signing_key_path is not None:
        key = security.load_release_private_key(signing_key_path)
        _write_staged_signature(staged, security.ed25519_sign(key.seed, sidecar_bytes))
        print(f"[+] Signed canonical GeoIP sidecar with {key.signer_id}; geoip.csv.sig staged")

    print(f"[+] GeoIP dataset digest verified before replacement: {actual}")


def _install_owner_and_mode(path: Path) -> None:
    try:
        os.chmod(path, 0o640)
        # Attempt to chown to gedefense:gedefense if running as root
        if os.geteuid() == 0:
            import pwd, grp
            uid = pwd.getpwnam("gedefense").pw_uid
            gid = grp.getgrnam("gedefense").gr_gid
            os.chown(path, uid, gid)
    except Exception:
        pass


def commit_staged_dataset(staged: StagedGeoIPDataset) -> Path:
    """Atomically install an already authenticated staged dataset.

    Only called after ``authenticate_staged_dataset`` succeeded. The CSV is
    replaced first and the sidecar immediately after it, so a crash window can
    only ever leave a dataset whose sidecar does not match: the runtime fails
    closed instead of silently accepting unverified data.
    """
    target_path = staged.target_path
    sidecar_target = target_path.with_name(target_path.name + ".sha256")
    signature_target = target_path.with_name(target_path.name + ".sig")
    previous_signature = signature_target.exists()
    try:
        os.replace(staged.csv_path, target_path)
        _install_owner_and_mode(target_path)
        os.replace(staged.sidecar_path, sidecar_target)
        _install_owner_and_mode(sidecar_target)
        if staged.signature_path is not None:
            os.replace(staged.signature_path, signature_target)
            _install_owner_and_mode(signature_target)
    finally:
        staged.cleanup()
    if staged.signature_path is None and previous_signature:
        print(
            f"[!] WARNING: a previous {signature_target.name} remains installed but does not cover the new dataset; "
            "runtimes with pinned update keys will reject the dataset until a matching signature is installed",
            file=sys.stderr,
        )
    try:
        directory_fd = os.open(target_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass
    print(f"[+] Successfully installed: {target_path}")
    print(f"[+] SHA-256: {staged.sha256}")
    print(f"[+] Canonical sidecar: {sidecar_target}")
    if staged.signature_path is not None:
        print(f"[+] Signature: {signature_target}")
    return target_path


def install_geoip_dataset(
    ranges_v4: list[MergedRange],
    ranges_v6: list[MergedRange],
    target_path: Path,
    *,
    expected_sha256: str = "",
    signature_path: Optional[Path] = None,
    verify_key_path: Optional[Path] = None,
    signing_key_path: Optional[Path] = None,
) -> Path:
    """Stage, authenticate and only then atomically install the GeoIP dataset."""
    staged = stage_geoip_dataset(ranges_v4, ranges_v6, Path(target_path))
    try:
        authenticate_staged_dataset(
            staged,
            expected_sha256=expected_sha256,
            signature_path=signature_path,
            verify_key_path=verify_key_path,
            signing_key_path=signing_key_path,
        )
    except BaseException:
        staged.cleanup()
        raise
    return commit_staged_dataset(staged)


def main() -> int:
    parser = argparse.ArgumentParser(description="VGT GeDefense Local GeoIP/ASN Database Generator")
    parser.add_argument("dest", nargs="?", default="/var/lib/vgt/gedefense/geoip.csv", help="Destination CSV path")
    parser.add_argument("--cache-dir", default="", help=f"Private 0700 download cache directory (default: {DEFAULT_CACHE_DIR}; no /tmp fallback)")
    parser.add_argument("--force", action="store_true", help="Force re-download of raw datasets")
    parser.add_argument("--expected-sha256", default="", help="Pinned SHA-256 of the generated combined CSV (verified before installation, fail closed on mismatch)")
    parser.add_argument("--signature", default="", help="Base64 Ed25519 signature over the canonical geoip.csv.sha256 JSON sidecar (pinned mirror key)")
    parser.add_argument("--verify-key", default="", help="Pinned raw Ed25519 public key for --signature")
    parser.add_argument("--signing-key", default="", help="Optional raw 0600 Ed25519 private key to sign the canonical sidecar and install geoip.csv.sig")
    args = parser.parse_args()

    try:
        cache_dir = resolve_cache_dir(args.cache_dir)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    dest = Path(args.dest).expanduser()
    if not (args.expected_sha256 or (args.signature and args.verify_key) or args.signing_key):
        print(
            "[!] WARNING: no --expected-sha256, --signature/--verify-key or --signing-key supplied; "
            "the generated dataset is installed without an operator pin. Raw upstream downloads are "
            "untrusted inputs; release automation must pin the output digest/signature.",
            file=sys.stderr,
        )

    print("============================================================")
    print("VGT GeDefense 6.0.1 — GeoIP & ASN Database Pipeline")
    print("============================================================")
    print(f"Target destination: {dest}")
    print(f"Private cache dir:  {cache_dir}")

    try:
        # 1. Download/Fetch origin ASN CIDRs into the private cache
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

        # 5. Stage into private 0700, authenticate digest + signature, only then
        #    atomically install. A verification error never replaces the dataset.
        install_geoip_dataset(
            ranges_v4,
            ranges_v6,
            dest,
            expected_sha256=args.expected_sha256,
            signature_path=Path(args.signature) if args.signature else None,
            verify_key_path=Path(args.verify_key) if args.verify_key else None,
            signing_key_path=Path(args.signing_key) if args.signing_key else None,
        )
    except RuntimeError as error:
        print(f"ERROR: GeoIP update aborted, installed dataset left untouched: {error}", file=sys.stderr)
        return 2

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

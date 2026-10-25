#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 VisionGaia Technology
# SPDX-License-Identifier: AGPL-3.0-only
#
# post-update-rebaseline.sh — authorized FIM/Titan rebaseline after a verified
# release update.
#
# The updater calls this once the new release is deployed under
# /opt/vgt/gedefense/current and the platform reports the verified release gate
# (enforce, fail-safe verified, kernel policy verified). The script performs the
# one operator action the integrity fabric accepts for a release change and then
# verifies the postconditions instead of trusting the HTTP 200:
#
#   1. POST /api/v1/fim/baseline  {scope: release, reason, confirm}
#      -> rebaselines only the release artifacts and the deployed config file,
#         records the old/new digests in the event journal and accepts the Titan
#         findings covered by the new baseline.
#   2. GET  /api/v1/status
#      -> requires fim.health == VERIFIED and titan.open_findings == 0.
#
# Exit codes: 0 success, 1 rebaseline/verification failure, 2 usage/config error.
# The dashboard token is read from disk and never printed.

set -Eeuo pipefail
IFS=$'\n\t'

TOKEN_FILE="/var/lib/vgt/gedefense/dashboard.token"
ENDPOINT="http://127.0.0.1:9844"
REASON=""
CONFIRM_PHRASE="REBASELINE RELEASE"
TIMEOUT_SECONDS=180
DRY_RUN=0

usage() {
	cat <<'USAGE'
Usage: post-update-rebaseline.sh --reason TEXT [options]

  --reason TEXT        Operator reason recorded with the rebaseline (>= 8 chars).
  --token-file PATH    Dashboard token file (default: /var/lib/vgt/gedefense/dashboard.token).
  --endpoint URL       Control-plane endpoint (default: http://127.0.0.1:9844).
  --timeout SECONDS    Per-request timeout (default: 180).
  --dry-run            Validate configuration and print the plan without mutating.
  -h, --help           This help.

The release gate must already be verified; the control plane refuses the
rebaseline otherwise and this script exits non-zero.
USAGE
}

fail() {
	printf 'post-update-rebaseline: %s\n' "$1" >&2
	exit "${2:-1}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--reason)
			[[ $# -ge 2 ]] || fail "--reason requires a value" 2
			REASON=$2
			shift 2
			;;
		--token-file)
			[[ $# -ge 2 ]] || fail "--token-file requires a value" 2
			TOKEN_FILE=$2
			shift 2
			;;
		--endpoint)
			[[ $# -ge 2 ]] || fail "--endpoint requires a value" 2
			ENDPOINT=$2
			shift 2
			;;
		--timeout)
			[[ $# -ge 2 ]] || fail "--timeout requires a value" 2
			TIMEOUT_SECONDS=$2
			shift 2
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			fail "unknown argument: $1" 2
			;;
	esac
done

[[ -n "${REASON// /}" ]] || fail "--reason is required" 2
[[ ${#REASON} -ge 8 ]] || fail "--reason must be at least 8 characters" 2
[[ ${#REASON} -le 240 ]] || fail "--reason must be at most 240 characters" 2
case "$REASON" in
	*'"'*|*'\'*|*$'\n'*|*$'\r'*) fail "--reason must not contain quotes, backslashes or line breaks" 2 ;;
esac
[[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || fail "--timeout must be a whole number of seconds" 2
[[ "$ENDPOINT" =~ ^https?://[A-Za-z0-9._:/-]+$ ]] || fail "--endpoint must be an http(s) URL" 2
command -v curl >/dev/null 2>&1 || fail "curl is required" 2

[[ -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" ]] || fail "token file is missing, not a regular file or a symlink" 1
[[ -r "$TOKEN_FILE" ]] || fail "token file is not readable" 1
token=$(tr -d '\r\n' < "$TOKEN_FILE")
[[ -n "$token" ]] || fail "token file is empty" 1
[[ ${#token} -ge 16 ]] || fail "token file does not contain a plausible token" 1

payload=$(printf '{"scope":"release","reason":"%s","confirm":"%s"}' "$REASON" "$CONFIRM_PHRASE")

if [[ "$DRY_RUN" -eq 1 ]]; then
	printf 'post-update-rebaseline: dry-run\n  endpoint=%s\n  token-file=%s\n  payload=%s\n' \
		"$ENDPOINT" "$TOKEN_FILE" "$payload"
	exit 0
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
response="$workdir/rebaseline.json"
status_body="$workdir/status.json"

http_code=$(curl -sS --max-time "$TIMEOUT_SECONDS" -o "$response" -w '%{http_code}' \
	-X POST "$ENDPOINT/api/v1/fim/baseline" \
	-H "Authorization: Bearer ${token}" \
	-H 'Content-Type: application/json' \
	--data-binary "$payload") || fail "rebaseline request failed (control plane unreachable?)" 1
if [[ "$http_code" != "200" ]]; then
	printf 'post-update-rebaseline: rebaseline rejected (HTTP %s)\n' "$http_code" >&2
	head -c 1200 "$response" >&2
	printf '\n' >&2
	exit 1
fi
if ! grep -q '"remaining_deviations":0' "$response"; then
	printf 'post-update-rebaseline: rebaseline left deviations outside the accepted release scope\n' >&2
	head -c 1200 "$response" >&2
	printf '\n' >&2
	exit 1
fi
generation=$(sed -n 's/.*"generation":\([0-9][0-9]*\).*/\1/p' "$response" | head -n 1)
titan_closed=$(sed -n 's/.*"closed_findings":\([0-9][0-9]*\).*/\1/p' "$response" | head -n 1)

status_code=$(curl -sS --max-time "$TIMEOUT_SECONDS" -o "$status_body" -w '%{http_code}' \
	-H "Authorization: Bearer ${token}" "$ENDPOINT/api/v1/status") || fail "status request failed" 1
[[ "$status_code" == "200" ]] || fail "status endpoint answered HTTP $status_code after the rebaseline" 1
if ! grep -q '"health":"VERIFIED"' "$status_body"; then
	fail "FIM health is not VERIFIED after the rebaseline"
fi
if ! grep -q '"open_findings":0' "$status_body"; then
	fail "Titan still reports open findings after the rebaseline"
fi

printf 'post-update-rebaseline: ok generation=%s fim=VERIFIED titan_open_findings=0 titan_closed=%s\n' \
	"${generation:-unknown}" "${titan_closed:-0}"

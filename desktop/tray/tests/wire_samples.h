// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Wire samples for the transport and validation tests.
//
// The samples live in a header on purpose: moc does not preprocess #include
// directives, so no raw string or escape sequence in here can confuse the
// meta-object compiler. Everything the tests feed to the client comes from this
// single place.

#pragma once

#include <QByteArray>

namespace gedefense::samples {

// --- valid payloads --------------------------------------------------------
inline constexpr auto kFullReply = R"({
  "v": 1,
  "status": "secure",
  "status_reason": "Alle Schutzschichten aktiv",
  "generated_at": "2026-10-16T14:57:03Z",
  "product_version": "4.4.0",
  "node_name": "visiongaia.de",
  "release_phase": "enforce",
  "enforcement": "enforce",
  "kernel_policy": "verified-enforce",
  "ebpf_active": true,
  "sensor": "fanotify-exec+ebpf-exec+cgroup-egress+procfs-fallback",
  "threat_count_today": 18,
  "blocked_active": 288,
  "last_anomaly_at": "2026-10-16T14:15:00Z",
  "last_anomaly_summary": "Portscan verworfen",
  "active_alert": null
})";

inline constexpr auto kCompactReply
    = R"({"v":1,"status":"secure","status_reason":"Alle Schutzschichten aktiv","product_version":"4.4.0",)"
      R"("node_name":"visiongaia.de","ebpf_active":true,"blocked_active":288,"active_alert":null})";

inline constexpr auto kStateSecure = R"({"v":1,"status":"secure"})";
inline constexpr auto kStateWarning = R"({"v":1,"status":"warning"})";
inline constexpr auto kStateAlert = R"({"v":1,"status":"alert"})";
inline constexpr auto kStateStopped = R"({"v":1,"status":"stopped"})";
inline constexpr auto kStateUpper = R"({"v":1,"status":"SECURE"})";
inline constexpr auto kStateUnknownValue = R"({"v":1,"status":"whatever"})";
inline constexpr auto kStateMissing = R"({"v":1})";

inline constexpr auto kUnknownKeys
    = R"({"v":1,"status":"secure","evil":{"nested":[1,2,3]},"__proto__":"x","sensor":42})";

inline constexpr auto kWrongTypes = R"({
        "v": 1,
        "status": 7,
        "status_reason": 42,
        "generated_at": 12345,
        "product_version": [],
        "node_name": false,
        "release_phase": {},
        "enforcement": null,
        "kernel_policy": 3.5,
        "ebpf_active": "yes",
        "sensor": ["a"],
        "threat_count_today": "18",
        "blocked_active": {},
        "last_anomaly_at": true,
        "last_anomaly_summary": 9,
        "active_alert": [1,2]
    })";

inline constexpr auto kAlertFull = R"({
        "v": 1,
        "status": "alert",
        "active_alert": {
            "summary": "Portscan verworfen",
            "severity": "high",
            "since": "2026-10-16T14:15:00Z",
            "target": "10.0.0.4"
        }
    })";

inline constexpr auto kAlertNull = R"({"v":1,"status":"secure","active_alert":null})";
inline constexpr auto kAlertPartial = R"({"v":1,"status":"alert","active_alert":{"severity":5,"summary":""}})";
inline constexpr auto kAlertBadTimestamp = R"({"v":1,"status":"alert","active_alert":{"since":"not-a-date"}})";
inline constexpr auto kAlertBadType = R"({"v":1,"status":"active","active_alert":"boom"})";

// --- rejected payloads -----------------------------------------------------
inline constexpr auto kNonObjectArray = "[1,2,3]";
inline constexpr auto kNonObjectString = "\"secure\"";
inline constexpr auto kEmpty = "";
inline constexpr auto kNewlineOnly = "\n";
inline constexpr auto kGarbageText = "hello world";
inline constexpr auto kGarbageHtml = "<html><body>error</body></html>";
inline constexpr auto kGarbageTrailing = R"({"v":1} trailing)";
inline constexpr auto kTruncatedReply = R"({"v":1,"status":"sec)";
inline constexpr auto kUnterminatedReply = R"({"v":1,"status":"secure")";
inline constexpr auto kProtocolTwo = R"({"v":2,"status":"secure"})";
inline constexpr auto kGarbageReply = "<html>nope</html>";

inline constexpr auto kVersionMissing = R"({"status":"secure"})";
inline constexpr auto kVersionString = R"({"v":"1","status":"secure"})";
inline constexpr auto kVersionNull = R"({"v":null})";
inline constexpr auto kVersionFuture = R"({"v":2})";
inline constexpr auto kVersionFraction = R"({"v":1.5})";
inline constexpr auto kVersionZero = R"({"v":0})";

inline constexpr auto kCountersInvalid = R"({"v":1,"threat_count_today":-5,"blocked_active":1.5})";
inline constexpr auto kCountersHuge = R"({"v":1,"threat_count_today":100000000000000000000})";
inline constexpr auto kCountersBoundary = R"({"v":1,"blocked_active":0,"threat_count_today":999999999999})";

inline constexpr auto kControlCharacters
    = R"({"v":1,"status":"alert","status_reason":"Zeile1\nZeile2\t<u>markup</u>\u202Eevil\u0007"})";

inline constexpr auto kLongReasonPrefix = R"({"v":1,"status":"warning","status_reason":")";
inline constexpr auto kLongReasonSuffix = R"("})";
inline constexpr auto kBoundReplyPrefix = R"({"v":1,"status_reason":")";
inline constexpr auto kBoundReplySuffix = R"("})";
inline constexpr auto kInvalidUtf8Prefix = R"({"v":1,"status":"secure","node_name":")";
inline constexpr auto kInvalidUtf8Suffix = R"("node"})";

// --- request line ----------------------------------------------------------
inline constexpr auto kStatusRequest = "{\"v\":1,\"op\":\"status\"}\n";

// --- helpers ---------------------------------------------------------------
inline QByteArray binaryGarbage()
{
    QByteArray sample;
    sample.append('\0');
    sample.append('\x01');
    sample.append('\x02');
    sample.append("binary");
    return sample;
}

inline QByteArray withNewline(const QByteArray& body)
{
    QByteArray line = body;
    line.append('\n');
    return line;
}

} // namespace gedefense::samples

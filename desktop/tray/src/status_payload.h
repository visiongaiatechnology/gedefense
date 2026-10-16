// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Strictly validated interpretation of the FROZEN WIRE CONTRACT v1 status
// response. This translation unit is the ONLY place in the client where JSON
// is parsed. Every field is optional, every value is hostile input: type,
// range and length are validated, unknown keys are ignored, oversized replies
// and malformed JSON are rejected instead of partially applied.

#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QMetaType>
#include <QString>

#include <optional>

namespace gedefense {

// Protocol version of the frozen wire contract.
inline constexpr int kWireProtocolVersion = 1;

// Bounded reads: one request line, one reply line.
inline constexpr int kMaximumRequestBytes = 256;
inline constexpr int kMaximumReplyBytes = 4096;

// Field length bounds (characters after sanitisation).
inline constexpr int kMaximumShortFieldLength = 120;
inline constexpr int kMaximumTextFieldLength = 240;
inline constexpr int kMaximumSensorFieldLength = 160;

// Maximum accepted length of an ISO-8601 timestamp before parsing.
inline constexpr int kMaximumTimestampLength = 40;

// Numeric range bound for counters.
inline constexpr qint64 kMaximumCounterValue = 999999999999LL;

// Client-side state. `Stopped` is defined by the client itself whenever the
// daemon does not answer - the UI must never show a healthy state just because
// nothing replied.
enum class StatusState
{
    Unknown,
    Secure,
    Warning,
    Alert,
    Stopped
};

struct ActiveAlert
{
    bool present = false;
    QString summary;
    QString severity;
    QString target;
    QDateTime since;
};

struct StatusPayload
{
    // True when the reply was a well-formed object carrying protocol version 1.
    bool valid = false;
    StatusState state = StatusState::Unknown;
    QString statusReason;
    QDateTime generatedAt;
    QString productVersion;
    QString nodeName;
    QString releasePhase;
    QString enforcement;
    QString kernelPolicy;
    std::optional<bool> ebpfActive;
    QString sensor;
    std::optional<qint64> threatCountToday;
    std::optional<qint64> blockedActive;
    QDateTime lastAnomalyAt;
    QString lastAnomalySummary;
    ActiveAlert activeAlert;
    // Set by the client when the last successful answer is older than the
    // staleness window.
    bool stale = false;
};

// Reason why a reply line was rejected. Stable classification used for tests,
// logging and user-facing failure mapping - never displayed verbatim.
enum class ParseFailure
{
    None,
    Empty,
    TooLarge,
    MalformedJson,
    NotAnObject,
    VersionMissing,
    VersionUnsupported
};

// Parses one reply line. Returns std::nullopt when the line is empty, exceeds
// the reply bound, is not valid UTF-8 JSON, is not an object, or does not carry
// the expected protocol version. `failure` receives the stable classification.
std::optional<StatusPayload> parseStatusLine(const QByteArray& line, ParseFailure* failure = nullptr);

// Stable, non-translated wire key ("secure", "warning", ...). Used for tests,
// icon selection and object properties - never for display.
QString statusStateKey(StatusState state);

// Removes control characters (including Unicode bidi overrides), collapses
// nothing, bounds the length and appends an ellipsis when truncation occurred.
// Exposed for reuse by the presentation layer when it applies soft line breaks.
QString sanitizeUntrustedText(const QString& raw, int maximumLength);

} // namespace gedefense

Q_DECLARE_METATYPE(gedefense::StatusPayload)
Q_DECLARE_METATYPE(gedefense::StatusState)

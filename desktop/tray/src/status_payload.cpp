// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include "status_payload.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QString>

#include <cmath>

namespace gedefense {
namespace {

constexpr QChar::Category kControlCategory = QChar::Other_Control;
constexpr QChar::Category kFormatCategory = QChar::Other_Format;
constexpr ushort kLineSeparator = 0x2028U;
constexpr ushort kParagraphSeparator = 0x2029U;
constexpr ushort kEllipsis = 0x2026U;

bool isNonSpacingControl(const QChar character)
{
    if (character.category() == kControlCategory || character.category() == kFormatCategory)
    {
        return true;
    }
    const ushort value = character.unicode();
    return value == kLineSeparator || value == kParagraphSeparator;
}

void setFailure(ParseFailure* failure, ParseFailure value)
{
    if (failure != nullptr)
    {
        *failure = value;
    }
}

// Reads a string member with a strict type check. Wrong types are ignored
// (treated as absent) instead of being coerced.
std::optional<QString> readString(const QJsonObject& object, const QString& key, int maximumLength)
{
    const QJsonValue value = object.value(key);
    if (!value.isString())
    {
        return std::nullopt;
    }
    return sanitizeUntrustedText(value.toString(), maximumLength);
}

// Reads a boolean member with a strict type check.
std::optional<bool> readBool(const QJsonObject& object, const QString& key)
{
    const QJsonValue value = object.value(key);
    if (!value.isBool())
    {
        return std::nullopt;
    }
    return value.toBool();
}

// Reads a non-negative integral counter inside the accepted range. Fractions,
// negative values, non-finite values, strings and objects are rejected.
std::optional<qint64> readCounter(const QJsonObject& object, const QString& key)
{
    const QJsonValue value = object.value(key);
    if (!value.isDouble())
    {
        return std::nullopt;
    }
    const double raw = value.toDouble();
    if (!std::isfinite(raw))
    {
        return std::nullopt;
    }
    if (raw < 0.0 || raw > static_cast<double>(kMaximumCounterValue))
    {
        return std::nullopt;
    }
    if (std::floor(raw) != raw)
    {
        return std::nullopt;
    }
    return static_cast<qint64>(raw);
}

// Reads an ISO-8601 timestamp. Anything that does not parse is treated as
// absent; the raw text is never kept, so no unvalidated string can reach a
// label.
std::optional<QDateTime> readTimestamp(const QJsonObject& object, const QString& key)
{
    const QJsonValue value = object.value(key);
    if (!value.isString())
    {
        return std::nullopt;
    }
    const QString text = value.toString();
    if (text.isEmpty() || text.size() > kMaximumTimestampLength)
    {
        return std::nullopt;
    }
    const QDateTime parsed = QDateTime::fromString(text, Qt::ISODate);
    if (!parsed.isValid())
    {
        return std::nullopt;
    }
    return parsed;
}

StatusState readState(const std::optional<QString>& status)
{
    if (!status.has_value())
    {
        return StatusState::Unknown;
    }
    const QString lowered = status->trimmed().toLower();
    if (lowered == QStringLiteral("secure"))
    {
        return StatusState::Secure;
    }
    if (lowered == QStringLiteral("warning"))
    {
        return StatusState::Warning;
    }
    if (lowered == QStringLiteral("alert"))
    {
        return StatusState::Alert;
    }
    if (lowered == QStringLiteral("stopped"))
    {
        return StatusState::Stopped;
    }
    return StatusState::Unknown;
}

void readActiveAlert(const QJsonObject& root, StatusPayload& payload)
{
    const QJsonValue value = root.value(QStringLiteral("active_alert"));
    if (value.isNull() || value.isUndefined() || !value.isObject())
    {
        return;
    }
    const QJsonObject alert = value.toObject();
    ActiveAlert parsed;
    parsed.present = true;
    if (const auto summary = readString(alert, QStringLiteral("summary"), kMaximumTextFieldLength))
    {
        parsed.summary = *summary;
    }
    if (const auto severity = readString(alert, QStringLiteral("severity"), kMaximumShortFieldLength))
    {
        parsed.severity = *severity;
    }
    if (const auto target = readString(alert, QStringLiteral("target"), kMaximumShortFieldLength))
    {
        parsed.target = *target;
    }
    if (const auto since = readTimestamp(alert, QStringLiteral("since")))
    {
        parsed.since = *since;
    }
    payload.activeAlert = parsed;
}

} // namespace

QString sanitizeUntrustedText(const QString& raw, int maximumLength)
{
    if (maximumLength <= 0)
    {
        return QString();
    }
    QString sanitized;
    sanitized.reserve(raw.size() < maximumLength ? raw.size() : maximumLength + 1);
    int kept = 0;
    bool truncated = false;
    for (const QChar character : raw)
    {
        if (isNonSpacingControl(character))
        {
            continue;
        }
        if (kept >= maximumLength)
        {
            truncated = true;
            break;
        }
        sanitized.append(character);
        ++kept;
    }
    if (truncated)
    {
        sanitized.append(QChar(kEllipsis));
    }
    return sanitized;
}

std::optional<StatusPayload> parseStatusLine(const QByteArray& line, ParseFailure* failure)
{
    setFailure(failure, ParseFailure::None);

    if (line.size() > static_cast<qsizetype>(kMaximumReplyBytes))
    {
        setFailure(failure, ParseFailure::TooLarge);
        return std::nullopt;
    }

    QByteArray trimmed = line;
    while (!trimmed.isEmpty() && (trimmed.endsWith('\n') || trimmed.endsWith('\r')))
    {
        trimmed.chop(1);
    }
    if (trimmed.isEmpty())
    {
        setFailure(failure, ParseFailure::Empty);
        return std::nullopt;
    }

    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(trimmed, &parseError);
    if (parseError.error != QJsonParseError::NoError)
    {
        setFailure(failure, ParseFailure::MalformedJson);
        return std::nullopt;
    }
    if (!document.isObject())
    {
        setFailure(failure, ParseFailure::NotAnObject);
        return std::nullopt;
    }

    const QJsonObject root = document.object();
    const QJsonValue version = root.value(QStringLiteral("v"));
    if (!version.isDouble())
    {
        setFailure(failure, ParseFailure::VersionMissing);
        return std::nullopt;
    }
    const double versionValue = version.toDouble();
    if (!std::isfinite(versionValue) || std::floor(versionValue) != versionValue
        || static_cast<qint64>(versionValue) != static_cast<qint64>(kWireProtocolVersion))
    {
        setFailure(failure, ParseFailure::VersionUnsupported);
        return std::nullopt;
    }

    StatusPayload payload;
    payload.valid = true;

    const std::optional<QString> status
        = readString(root, QStringLiteral("status"), kMaximumShortFieldLength);
    payload.state = readState(status);

    if (const auto reason = readString(root, QStringLiteral("status_reason"), kMaximumTextFieldLength))
    {
        payload.statusReason = *reason;
    }
    if (const auto generated = readTimestamp(root, QStringLiteral("generated_at")))
    {
        payload.generatedAt = *generated;
    }
    if (const auto product = readString(root, QStringLiteral("product_version"), kMaximumShortFieldLength))
    {
        payload.productVersion = *product;
    }
    if (const auto node = readString(root, QStringLiteral("node_name"), kMaximumShortFieldLength))
    {
        payload.nodeName = *node;
    }
    if (const auto phase = readString(root, QStringLiteral("release_phase"), kMaximumShortFieldLength))
    {
        payload.releasePhase = *phase;
    }
    if (const auto enforcement = readString(root, QStringLiteral("enforcement"), kMaximumShortFieldLength))
    {
        payload.enforcement = *enforcement;
    }
    if (const auto kernelPolicy = readString(root, QStringLiteral("kernel_policy"), kMaximumShortFieldLength))
    {
        payload.kernelPolicy = *kernelPolicy;
    }
    payload.ebpfActive = readBool(root, QStringLiteral("ebpf_active"));
    if (const auto sensor = readString(root, QStringLiteral("sensor"), kMaximumSensorFieldLength))
    {
        payload.sensor = *sensor;
    }
    payload.threatCountToday = readCounter(root, QStringLiteral("threat_count_today"));
    payload.blockedActive = readCounter(root, QStringLiteral("blocked_active"));
    if (const auto anomaly = readTimestamp(root, QStringLiteral("last_anomaly_at")))
    {
        payload.lastAnomalyAt = *anomaly;
    }
    if (const auto summary = readString(root, QStringLiteral("last_anomaly_summary"), kMaximumTextFieldLength))
    {
        payload.lastAnomalySummary = *summary;
    }
    readActiveAlert(root, payload);

    return payload;
}

QString statusStateKey(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return QStringLiteral("secure");
    case StatusState::Warning:
        return QStringLiteral("warning");
    case StatusState::Alert:
        return QStringLiteral("alert");
    case StatusState::Stopped:
        return QStringLiteral("stopped");
    case StatusState::Unknown:
        break;
    }
    return QStringLiteral("unknown");
}

} // namespace gedefense

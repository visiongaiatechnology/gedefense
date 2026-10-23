// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include "status_client.h"

#include "app_paths.h"

#include <QLocalSocket>
#include <QRandomGenerator>
#include <QString>

#include <algorithm>
#include <cmath>
#include <cstddef>

namespace gedefense {
namespace {

// The complete request as mandated by the frozen contract.
constexpr char kRequestLine[] = "{\"v\":1,\"op\":\"status\"}\n";
static_assert(sizeof(kRequestLine) - 1 <= static_cast<std::size_t>(kMaximumRequestBytes),
              "status request must stay within the 256 byte contract limit");

constexpr int kMinimumIntervalMs = 100;
constexpr double kJitterRatio = 0.25;

int clampInterval(int value, int lower, int upper)
{
    return std::max(lower, std::min(value, upper));
}

FailureKind failureKindForParse(ParseFailure failure)
{
    switch (failure)
    {
    case ParseFailure::TooLarge:
        return FailureKind::ReplyTooLarge;
    case ParseFailure::VersionMissing:
    case ParseFailure::VersionUnsupported:
        return FailureKind::IncompatibleProtocol;
    case ParseFailure::Empty:
    case ParseFailure::MalformedJson:
    case ParseFailure::NotAnObject:
        return FailureKind::MalformedReply;
    case ParseFailure::None:
        break;
    }
    return FailureKind::MalformedReply;
}

FailureKind failureKindForSocketError(QLocalSocket::LocalSocketError error)
{
    switch (error)
    {
    case QLocalSocket::ConnectionRefusedError:
    case QLocalSocket::ServerNotFoundError:
        return FailureKind::Unreachable;
    case QLocalSocket::SocketAccessError:
        return FailureKind::AccessDenied;
    case QLocalSocket::SocketTimeoutError:
        return FailureKind::Timeout;
    case QLocalSocket::PeerClosedError:
        return FailureKind::MalformedReply;
    default:
        break;
    }
    return FailureKind::TransportFailure;
}

} // namespace

StatusClient::StatusClient(QObject* parent)
    : StatusClient(ClientTimings{}, parent)
{
}

StatusClient::StatusClient(const ClientTimings& timings, QObject* parent)
    : QObject(parent)
    , m_timings(normalizedTimings(timings))
    , m_resolution(resolveSocketPath())
    , m_socket(new QLocalSocket(this))
{
    qRegisterMetaType<gedefense::StatusPayload>("gedefense::StatusPayload");
    qRegisterMetaType<gedefense::StatusState>("gedefense::StatusState");

    m_pollTimer.setSingleShot(true);
    m_timeoutTimer.setSingleShot(true);
    m_staleTimer.setSingleShot(true);

    connect(&m_pollTimer, &QTimer::timeout, this, &StatusClient::beginRequest);
    connect(&m_timeoutTimer, &QTimer::timeout, this, &StatusClient::onRequestTimeout);
    connect(&m_staleTimer, &QTimer::timeout, this, &StatusClient::onStaleElapsed);
    connect(m_socket, &QLocalSocket::connected, this, &StatusClient::onConnected);
    connect(m_socket, &QLocalSocket::readyRead, this, &StatusClient::onReadyRead);
    connect(m_socket, &QLocalSocket::disconnected, this, &StatusClient::onDisconnected);
    connect(m_socket, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError)
            { onSocketError(); });
}

StatusClient::~StatusClient()
{
    stop();
}

ClientTimings StatusClient::normalizedTimings(const ClientTimings& timings)
{
    ClientTimings normalized = timings;
    normalized.pollIntervalMs = std::max(kMinimumIntervalMs, timings.pollIntervalMs);
    normalized.requestTimeoutMs = std::max(kMinimumIntervalMs, timings.requestTimeoutMs);
    normalized.staleAfterMs = std::max(normalized.pollIntervalMs, timings.staleAfterMs);
    normalized.backoffMinimumMs = std::max(kMinimumIntervalMs, timings.backoffMinimumMs);
    normalized.backoffMaximumMs = std::max(normalized.backoffMinimumMs, timings.backoffMaximumMs);
    return normalized;
}

SocketPathResolution StatusClient::resolveSocketPath()
{
    SocketPathResolution resolution;
    const QByteArray configured = qgetenv(paths::kSocketPathEnvironmentVariable);

    if (configured.isEmpty())
    {
        resolution.path = QString::fromLatin1(paths::kProductionSocketPath);
        resolution.acceptable = true;
        resolution.fromEnvironment = false;
        return resolution;
    }

    const QString candidate = QString::fromUtf8(configured);
    resolution.path = candidate;
    resolution.acceptable = paths::isAcceptableSocketPath(candidate);
    resolution.fromEnvironment = true;
    return resolution;
}

int StatusClient::backoffDelayMs(int failedAttempts, const ClientTimings& timings, double jitterFraction)
{
    const ClientTimings bounds = normalizedTimings(timings);
    if (failedAttempts <= 0)
    {
        return bounds.backoffMinimumMs;
    }

    int delay = bounds.backoffMinimumMs;
    for (int attempt = 1; attempt < failedAttempts; ++attempt)
    {
        if (delay > bounds.backoffMaximumMs / 2)
        {
            delay = bounds.backoffMaximumMs;
            break;
        }
        delay *= 2;
    }
    delay = std::min(delay, bounds.backoffMaximumMs);

    const double fraction = std::max(-1.0, std::min(1.0, jitterFraction));
    const double jittered = static_cast<double>(delay) * (1.0 + kJitterRatio * fraction);
    const int rounded = static_cast<int>(std::lround(jittered));
    return clampInterval(rounded, bounds.backoffMinimumMs, bounds.backoffMaximumMs);
}

void StatusClient::start()
{
    if (m_running)
    {
        return;
    }
    m_running = true;
    m_failedAttempts = 0;
    beginRequest();
}

void StatusClient::stop()
{
    m_running = false;
    m_inFlight = false;
    m_requestCompleted = false;
    m_pollTimer.stop();
    m_timeoutTimer.stop();
    m_staleTimer.stop();
    if (m_socket->state() != QLocalSocket::UnconnectedState)
    {
        m_socket->abort();
    }
    m_buffer.clear();
}

bool StatusClient::isRunning() const
{
    return m_running;
}

bool StatusClient::hasPayload() const
{
    return m_hasSuccess;
}

bool StatusClient::isStale() const
{
    return m_hasSuccess && m_payload.stale;
}

StatusPayload StatusClient::lastPayload() const
{
    return m_payload;
}

qint64 StatusClient::millisecondsSinceLastSuccess() const
{
    if (!m_hasSuccess || !m_sinceLastSuccess.isValid())
    {
        return -1;
    }
    return m_sinceLastSuccess.elapsed();
}

FailureKind StatusClient::lastFailureKind() const
{
    return m_lastFailure;
}

SocketPathResolution StatusClient::socketResolution() const
{
    return m_resolution;
}

ClientTimings StatusClient::timings() const
{
    return m_timings;
}

void StatusClient::requestImmediate()
{
    if (!m_running)
    {
        start();
        return;
    }
    m_failedAttempts = 0;
    if (m_inFlight)
    {
        m_inFlight = false;
        m_timeoutTimer.stop();
        m_socket->abort();
    }
    m_pollTimer.stop();
    beginRequest();
}

void StatusClient::beginRequest()
{
    if (!m_running || m_inFlight)
    {
        return;
    }
    if (!m_resolution.acceptable)
    {
        reportFailure(FailureKind::InvalidSocketPath, reasonFor(FailureKind::InvalidSocketPath));
        return;
    }

    m_inFlight = true;
    m_requestCompleted = false;
    m_buffer.clear();
    if (m_socket->state() != QLocalSocket::UnconnectedState)
    {
        m_socket->abort();
    }
    m_socket->connectToServer(m_resolution.path);
    m_timeoutTimer.start(m_timings.requestTimeoutMs);
}

void StatusClient::onConnected()
{
    if (!m_inFlight)
    {
        return;
    }
    const QByteArray request(kRequestLine, static_cast<qsizetype>(sizeof(kRequestLine) - 1));
    if (m_socket->write(request) != request.size())
    {
        reportFailure(FailureKind::TransportFailure, reasonFor(FailureKind::TransportFailure));
        return;
    }
    m_socket->flush();
}

void StatusClient::onReadyRead()
{
    if (!m_inFlight)
    {
        return;
    }
    m_buffer += m_socket->readAll();
    if (m_buffer.size() > static_cast<qsizetype>(kMaximumReplyBytes))
    {
        reportFailure(FailureKind::ReplyTooLarge, reasonFor(FailureKind::ReplyTooLarge));
        return;
    }
    const qsizetype newline = m_buffer.indexOf('\n');
    if (newline >= 0)
    {
        completeWithLine(m_buffer.left(newline));
    }
}

void StatusClient::onDisconnected()
{
    if (!m_inFlight || m_requestCompleted)
    {
        return;
    }
    if (!m_buffer.isEmpty())
    {
        // The peer closed without a trailing newline; a complete line is still
        // accepted as long as it parses.
        completeWithLine(m_buffer);
        return;
    }
    reportFailure(FailureKind::MalformedReply, reasonFor(FailureKind::MalformedReply));
}

void StatusClient::onSocketError()
{
    if (!m_inFlight || m_requestCompleted)
    {
        return;
    }
    const QLocalSocket::LocalSocketError error = m_socket->error();
    const FailureKind kind = failureKindForSocketError(error);
    reportFailure(kind, reasonFor(kind));
}

void StatusClient::onRequestTimeout()
{
    if (!m_inFlight)
    {
        return;
    }
    reportFailure(FailureKind::Timeout, reasonFor(FailureKind::Timeout));
}

void StatusClient::onStaleElapsed()
{
    markStaleIfDue();
}

void StatusClient::completeWithLine(const QByteArray& line)
{
    m_inFlight = false;
    m_requestCompleted = true;
    m_timeoutTimer.stop();
    m_socket->abort();
    m_buffer.clear();

    ParseFailure parseFailure = ParseFailure::None;
    const std::optional<StatusPayload> parsed = parseStatusLine(line, &parseFailure);
    if (!parsed.has_value())
    {
        const FailureKind kind = failureKindForParse(parseFailure);
        reportFailure(kind, reasonFor(kind));
        return;
    }

    m_lastFailure = FailureKind::None;
    m_failedAttempts = 0;
    m_payload = *parsed;
    m_payload.stale = false;
    m_hasSuccess = true;
    m_sinceLastSuccess.restart();
    emit updated(m_payload);
    m_staleTimer.start(m_timings.staleAfterMs);
    scheduleNext(m_timings.pollIntervalMs);
}

void StatusClient::reportFailure(FailureKind kind, const QString& reason)
{
    m_inFlight = false;
    m_timeoutTimer.stop();
    m_socket->abort();
    m_buffer.clear();

    m_lastFailure = kind;
    ++m_failedAttempts;
    markStaleIfDue();
    emit unavailable(reason);

    const double jitterFraction = QRandomGenerator::global()->generateDouble() * 2.0 - 1.0;
    scheduleNext(backoffDelayMs(m_failedAttempts, m_timings, jitterFraction));
}

void StatusClient::scheduleNext(int delayMs)
{
    if (!m_running)
    {
        return;
    }
    m_pollTimer.start(delayMs);
}

void StatusClient::markStaleIfDue()
{
    if (!m_hasSuccess || m_payload.stale)
    {
        return;
    }
    if (m_sinceLastSuccess.elapsed() < m_timings.staleAfterMs)
    {
        return;
    }
    m_payload.stale = true;
    emit updated(m_payload);
}

QString StatusClient::reasonFor(FailureKind kind) const
{
    switch (kind)
    {
    case FailureKind::InvalidSocketPath:
        return tr("Der konfigurierte Socket-Pfad ist ungültig.");
    case FailureKind::Unreachable:
        return tr("Der GeDefense-Dienst ist nicht erreichbar.");
    case FailureKind::AccessDenied:
        return tr("Der Zugriff auf den Status-Socket wurde verweigert.");
    case FailureKind::Timeout:
        return tr("Der GeDefense-Dienst hat nicht rechtzeitig geantwortet.");
    case FailureKind::ReplyTooLarge:
        return tr("Die Antwort des Dienstes überschreitet das Größenlimit.");
    case FailureKind::MalformedReply:
        return tr("Die Antwort des Dienstes ist ungültig.");
    case FailureKind::IncompatibleProtocol:
        return tr("Die Protokollversion des Dienstes wird nicht unterstützt.");
    case FailureKind::TransportFailure:
    case FailureKind::None:
        break;
    }
    return tr("Die Statusabfrage ist fehlgeschlagen.");
}

} // namespace gedefense

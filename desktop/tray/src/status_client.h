// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// QLocalSocket transport for the FROZEN WIRE CONTRACT v1 status request.
//
// Guarantees:
//  * fully asynchronous (QLocalSocket only) - the GUI thread is never blocked
//  * exactly one in-flight request at a time
//  * hard bounds on request size, reply size and timeout
//  * bounded exponential backoff with jitter after failures (2 s .. 30 s)
//  * data is marked stale 15 s after the last successful answer
//  * the client itself owns the `Stopped` state: no answer never means healthy

#pragma once

#include "status_payload.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QObject>
#include <QString>
#include <QTimer>

class QLocalSocket;

namespace gedefense {

enum class FailureKind
{
    None,
    InvalidSocketPath,
    Unreachable,
    AccessDenied,
    Timeout,
    ReplyTooLarge,
    MalformedReply,
    IncompatibleProtocol,
    TransportFailure
};

struct ClientTimings
{
    int pollIntervalMs = 3000;
    int requestTimeoutMs = 2000;
    int staleAfterMs = 15000;
    int backoffMinimumMs = 2000;
    int backoffMaximumMs = 30000;
};

struct SocketPathResolution
{
    QString path;
    bool acceptable = false;
    bool fromEnvironment = false;
};

class StatusClient : public QObject
{
    Q_OBJECT

public:
    explicit StatusClient(QObject* parent = nullptr);
    explicit StatusClient(const ClientTimings& timings, QObject* parent = nullptr);
    ~StatusClient() override;

    StatusClient(const StatusClient&) = delete;
    StatusClient& operator=(const StatusClient&) = delete;

    // Starts polling. The first request is issued immediately.
    void start();
    void stop();

    // User initiated refresh: aborts a running request and restarts the cycle
    // with a reset backoff.
    void requestImmediate();

    bool isRunning() const;
    bool hasPayload() const;
    bool isStale() const;
    StatusPayload lastPayload() const;
    qint64 millisecondsSinceLastSuccess() const;
    FailureKind lastFailureKind() const;
    SocketPathResolution socketResolution() const;
    ClientTimings timings() const;

    // Pure computation, exposed for deterministic tests. `jitterFraction` is in
    // [-1, 1]; the result is always within [backoffMinimumMs, backoffMaximumMs].
    static int backoffDelayMs(int failedAttempts, const ClientTimings& timings, double jitterFraction);

    // Environment aware socket resolution (GEDEFENSE_TRAY_SOCKET).
    static SocketPathResolution resolveSocketPath();

    // Normalises a timings struct so that no unbounded or nonsensical value can
    // be configured.
    static ClientTimings normalizedTimings(const ClientTimings& timings);

signals:
    void updated(const gedefense::StatusPayload& payload);
    void unavailable(const QString& reason);

private:
    void beginRequest();
    void onConnected();
    void onReadyRead();
    void onDisconnected();
    void onSocketError();
    void onRequestTimeout();
    void onStaleElapsed();

    void completeWithLine(const QByteArray& line);
    void reportFailure(FailureKind kind, const QString& reason);
    void scheduleNext(int delayMs);
    void markStaleIfDue();
    QString reasonFor(FailureKind kind) const;

    ClientTimings m_timings;
    SocketPathResolution m_resolution;
    QLocalSocket* m_socket = nullptr;
    QTimer m_pollTimer;
    QTimer m_timeoutTimer;
    QTimer m_staleTimer;
    QElapsedTimer m_sinceLastSuccess;
    QByteArray m_buffer;
    StatusPayload m_payload;
    bool m_running = false;
    bool m_inFlight = false;
    bool m_requestCompleted = false;
    bool m_hasSuccess = false;
    int m_failedAttempts = 0;
    FailureKind m_lastFailure = FailureKind::None;
};

} // namespace gedefense

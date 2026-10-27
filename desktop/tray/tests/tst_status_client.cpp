// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Transport tests. The client is always driven against a real QLocalServer in a
// temporary directory - never against the production socket path.

#include "status_client.h"
#include "app_paths.h"
#include "wire_samples.h"

#include <QByteArray>
#include <QDir>
#include <QElapsedTimer>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QSet>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>

#include <memory>

using gedefense::ClientTimings;
using gedefense::FailureKind;
using gedefense::StatusClient;
using gedefense::StatusPayload;
using gedefense::StatusState;
using namespace gedefense::samples;

class FakeDaemon : public QObject
{
    Q_OBJECT

public:
    enum class Mode
    {
        ReplyImmediately,
        DelayReply,
        NeverReply,
        DropWithoutReply
    };

    explicit FakeDaemon(QObject* parent = nullptr)
        : QObject(parent)
        , m_server(new QLocalServer(this))
    {
        connect(m_server, &QLocalServer::newConnection, this, &FakeDaemon::onNewConnection);
    }

    bool listen(const QString& socketPath)
    {
        QLocalServer::removeServer(socketPath);
        return m_server->listen(socketPath);
    }

    void shutdown()
    {
        m_server->close();
        if (!m_server->fullServerName().isEmpty())
        {
            QLocalServer::removeServer(m_server->fullServerName());
        }
    }

    void setMode(Mode mode)
    {
        m_mode = mode;
    }

    void setReply(const QByteArray& reply)
    {
        m_reply = reply;
    }

    void setReplyDelayMs(int delayMs)
    {
        m_replyDelayMs = delayMs;
    }

    int connectionCount() const
    {
        return m_connectionCount;
    }

    QByteArray lastRequest() const
    {
        return m_lastRequest;
    }

private slots:
    void onNewConnection()
    {
        while (QLocalSocket* socket = m_server->nextPendingConnection())
        {
            ++m_connectionCount;
            connect(socket, &QLocalSocket::readyRead, this, [this, socket]() { consume(socket); });
            connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
            consume(socket);
        }
    }

private:
    void consume(QLocalSocket* socket)
    {
        const QByteArray chunk = socket->readAll();
        if (chunk.isEmpty())
        {
            return;
        }
        m_lastRequest += chunk;
        if (m_answered.contains(socket))
        {
            return;
        }
        m_answered.insert(socket);
        connect(socket, &QObject::destroyed, this, [this, socket]() { m_answered.remove(socket); });

        switch (m_mode)
        {
        case Mode::NeverReply:
            // Deliberately silent: the client must time out on its own.
            return;
        case Mode::DropWithoutReply:
            socket->disconnectFromServer();
            return;
        case Mode::DelayReply:
        {
            const QPointer<QLocalSocket> guard(socket);
            QTimer::singleShot(m_replyDelayMs, this, [this, guard]()
                               {
                                   if (guard != nullptr)
                                   {
                                       respond(guard);
                                   }
                               });
            return;
        }
        case Mode::ReplyImmediately:
            break;
        }
        respond(socket);
    }

    void respond(QLocalSocket* socket)
    {
        if (socket->state() != QLocalSocket::ConnectedState)
        {
            return;
        }
        socket->write(m_reply);
        socket->flush();
        socket->disconnectFromServer();
    }

    QLocalServer* m_server = nullptr;
    QSet<QLocalSocket*> m_answered;
    QByteArray m_reply;
    QByteArray m_lastRequest;
    Mode m_mode = Mode::ReplyImmediately;
    int m_replyDelayMs = 0;
    int m_connectionCount = 0;
};

class TestStatusClient : public QObject
{
    Q_OBJECT

private slots:
    void init();
    void cleanup();

    void pollsAndParsesReply();
    void sendsExactlyOneBoundedRequestLine();
    void reportsUnavailableWhenSocketIsMissing();
    void timesOutWhenServerStaysSilent();
    void reportsUnavailableWhenPeerDrops();
    void rejectsOversizedReply();
    void rejectsTruncatedJson();
    void rejectsNonJsonGarbage();
    void rejectsUnsupportedProtocolVersion();
    void marksDataStaleAfterThreshold();
    void keepsOneRequestInFlight();
    void backoffIsBoundedAndJittered();
    void backoffGrowsWithConsecutiveFailures();
    void resolvesSocketPathFromEnvironment();
    void refusesInvalidSocketPathFromEnvironment();
    void stopEndsPolling();

private:
    ClientTimings fastTimings() const;
    QString socketPath() const;

    std::unique_ptr<QTemporaryDir> m_directory;
};

ClientTimings TestStatusClient::fastTimings() const
{
    ClientTimings timings;
    timings.pollIntervalMs = 100;
    timings.requestTimeoutMs = 500;
    timings.staleAfterMs = 5000;
    timings.backoffMinimumMs = 100;
    timings.backoffMaximumMs = 400;
    return timings;
}

QString TestStatusClient::socketPath() const
{
    return m_directory->filePath(QStringLiteral("gedefense-test.sock"));
}

void TestStatusClient::init()
{
    m_directory = std::make_unique<QTemporaryDir>();
    QVERIFY(m_directory->isValid());
    qputenv("GEDEFENSE_TRAY_SOCKET", socketPath().toUtf8());
}

void TestStatusClient::cleanup()
{
    qunsetenv("GEDEFENSE_TRAY_SOCKET");
    m_directory.reset();
}

void TestStatusClient::pollsAndParsesReply()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kCompactReply)));

    StatusClient client(fastTimings());
    QSignalSpy updatedSpy(&client, &StatusClient::updated);
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    client.start();
    QVERIFY(updatedSpy.wait(5000));

    const auto payload = updatedSpy.at(0).at(0).value<StatusPayload>();
    QVERIFY(payload.valid);
    QCOMPARE(payload.state, StatusState::Secure);
    QCOMPARE(payload.productVersion, QStringLiteral("5.1.0-beta.2"));
    QCOMPARE(payload.nodeName, QStringLiteral("visiongaia.de"));
    QVERIFY(payload.ebpfActive.has_value());
    QCOMPARE(*payload.ebpfActive, true);
    QVERIFY(payload.blockedActive.has_value());
    QCOMPARE(*payload.blockedActive, 288LL);
    QVERIFY(!payload.stale);
    QCOMPARE(unavailableSpy.count(), 0);
    QCOMPARE(client.lastFailureKind(), FailureKind::None);
    QVERIFY(client.hasPayload());
    QCOMPARE(client.millisecondsSinceLastSuccess() >= 0, true);
    QCOMPARE(client.lastPayload().state, StatusState::Secure);
    client.stop();
}

void TestStatusClient::sendsExactlyOneBoundedRequestLine()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kCompactReply)));

    StatusClient client(fastTimings());
    QSignalSpy updatedSpy(&client, &StatusClient::updated);
    client.start();
    QVERIFY(updatedSpy.wait(5000));

    const QByteArray request = daemon.lastRequest();
    QCOMPARE(request, QByteArray(kStatusRequest));
    QVERIFY(request.size() <= gedefense::kMaximumRequestBytes);
    QCOMPARE(request.count('\n'), 1);
    client.stop();
}

void TestStatusClient::reportsUnavailableWhenSocketIsMissing()
{
    // No daemon is started: the socket file does not exist.
    StatusClient client(fastTimings());
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);
    QSignalSpy updatedSpy(&client, &StatusClient::updated);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QVERIFY(!unavailableSpy.at(0).at(0).toString().isEmpty());
    QCOMPARE(client.lastFailureKind(), FailureKind::Unreachable);
    QCOMPARE(updatedSpy.count(), 0);
    QVERIFY(!client.hasPayload());
    client.stop();
}

void TestStatusClient::timesOutWhenServerStaysSilent()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setMode(FakeDaemon::Mode::NeverReply);

    ClientTimings timings = fastTimings();
    timings.requestTimeoutMs = 300;
    StatusClient client(timings);
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    QElapsedTimer elapsed;
    elapsed.start();
    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::Timeout);
    QVERIFY(elapsed.elapsed() >= 250);
    client.stop();
}

void TestStatusClient::reportsUnavailableWhenPeerDrops()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setMode(FakeDaemon::Mode::DropWithoutReply);

    StatusClient client(fastTimings());
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::MalformedReply);
    client.stop();
}

void TestStatusClient::rejectsOversizedReply()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    // Far beyond the 4096 byte bound and without a newline.
    daemon.setReply(QByteArray(9000, 'x'));

    StatusClient client(fastTimings());
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);
    QSignalSpy updatedSpy(&client, &StatusClient::updated);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::ReplyTooLarge);
    QCOMPARE(updatedSpy.count(), 0);
    QVERIFY(!client.hasPayload());
    client.stop();
}

void TestStatusClient::rejectsTruncatedJson()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kTruncatedReply)));

    StatusClient client(fastTimings());
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::MalformedReply);
    client.stop();
}

void TestStatusClient::rejectsNonJsonGarbage()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kGarbageReply)));

    StatusClient client(fastTimings());
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::MalformedReply);
    client.stop();
}

void TestStatusClient::rejectsUnsupportedProtocolVersion()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kProtocolTwo)));

    StatusClient client(fastTimings());
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::IncompatibleProtocol);
    client.stop();
}

void TestStatusClient::marksDataStaleAfterThreshold()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kCompactReply)));

    ClientTimings timings = fastTimings();
    timings.staleAfterMs = 300;
    timings.pollIntervalMs = 50;
    timings.backoffMinimumMs = 50;
    timings.backoffMaximumMs = 100;

    StatusClient client(timings);
    QSignalSpy updatedSpy(&client, &StatusClient::updated);

    client.start();
    QVERIFY(updatedSpy.wait(5000));
    QVERIFY(!client.isStale());

    // The daemon disappears: the client must keep the last known state only
    // until the staleness window expires, then mark the data stale.
    daemon.shutdown();

    QTRY_VERIFY_WITH_TIMEOUT(client.isStale(), 4000);
    QVERIFY(client.lastPayload().stale);
    QCOMPARE(client.lastPayload().state, StatusState::Secure);

    bool sawStaleEmission = false;
    for (qsizetype index = 0; index < updatedSpy.count(); ++index)
    {
        const auto payload = updatedSpy.at(index).at(0).value<StatusPayload>();
        if (payload.stale)
        {
            sawStaleEmission = true;
            break;
        }
    }
    QVERIFY(sawStaleEmission);
    client.stop();
}

void TestStatusClient::keepsOneRequestInFlight()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setMode(FakeDaemon::Mode::DelayReply);
    daemon.setReplyDelayMs(250);
    daemon.setReply(withNewline(QByteArray(kCompactReply)));

    ClientTimings timings = fastTimings();
    timings.pollIntervalMs = 40;
    timings.requestTimeoutMs = 2000;

    StatusClient client(timings);
    client.start();
    QTest::qWait(1100);
    client.stop();

    // The poll interval (40 ms) is far shorter than the reply delay (250 ms):
    // without an in-flight guard the server would have seen ~27 connections.
    QVERIFY(daemon.connectionCount() >= 2);
    QVERIFY(daemon.connectionCount() <= 8);
}

void TestStatusClient::backoffIsBoundedAndJittered()
{
    ClientTimings timings;
    timings.backoffMinimumMs = 2000;
    timings.backoffMaximumMs = 30000;

    QCOMPARE(StatusClient::backoffDelayMs(0, timings, 0.0), 2000);
    QCOMPARE(StatusClient::backoffDelayMs(1, timings, 0.0), 2000);
    QCOMPARE(StatusClient::backoffDelayMs(2, timings, 0.0), 4000);
    QCOMPARE(StatusClient::backoffDelayMs(3, timings, 0.0), 8000);
    QCOMPARE(StatusClient::backoffDelayMs(4, timings, 0.0), 16000);
    QCOMPARE(StatusClient::backoffDelayMs(5, timings, 0.0), 30000);
    QCOMPARE(StatusClient::backoffDelayMs(50, timings, 0.0), 30000);

    // Jitter stays inside the documented corridor and never leaves the bounds.
    for (int attempt = 1; attempt <= 8; ++attempt)
    {
        const int low = StatusClient::backoffDelayMs(attempt, timings, -1.0);
        const int high = StatusClient::backoffDelayMs(attempt, timings, 1.0);
        QVERIFY(low >= 2000);
        QVERIFY(high <= 30000);
        QVERIFY(low <= high);
    }
    QCOMPARE(StatusClient::backoffDelayMs(3, timings, -1.0), 6000);
    QCOMPARE(StatusClient::backoffDelayMs(3, timings, 1.0), 10000);
}

void TestStatusClient::backoffGrowsWithConsecutiveFailures()
{
    ClientTimings timings;
    timings.backoffMinimumMs = 2000;
    timings.backoffMaximumMs = 30000;

    int previous = 0;
    for (int attempt = 1; attempt <= 5; ++attempt)
    {
        const int delay = StatusClient::backoffDelayMs(attempt, timings, 0.0);
        QVERIFY(delay >= previous);
        previous = delay;
    }
    QCOMPARE(previous, 30000);
}

void TestStatusClient::resolvesSocketPathFromEnvironment()
{
    qunsetenv("GEDEFENSE_TRAY_SOCKET");
    auto resolution = StatusClient::resolveSocketPath();
    QCOMPARE(resolution.path, QStringLiteral("/run/gedefense/gedefense.sock"));
    QVERIFY(resolution.acceptable);
    QVERIFY(!resolution.fromEnvironment);

    qputenv("GEDEFENSE_TRAY_SOCKET", QByteArray());
    resolution = StatusClient::resolveSocketPath();
    QCOMPARE(resolution.path, QStringLiteral("/run/gedefense/gedefense.sock"));
    QVERIFY(resolution.acceptable);
    QVERIFY(!resolution.fromEnvironment);

    const QString custom = socketPath();
    qputenv("GEDEFENSE_TRAY_SOCKET", custom.toUtf8());
    resolution = StatusClient::resolveSocketPath();
    QCOMPARE(resolution.path, custom);
    QVERIFY(resolution.acceptable);
    QVERIFY(resolution.fromEnvironment);

    qputenv("GEDEFENSE_TRAY_SOCKET", QByteArray("relative/path.sock"));
    resolution = StatusClient::resolveSocketPath();
    QVERIFY(!resolution.acceptable);
    QVERIFY(resolution.fromEnvironment);
    QCOMPARE(resolution.path, QStringLiteral("relative/path.sock"));

    qputenv("GEDEFENSE_TRAY_SOCKET", QByteArray("/") + QByteArray(200, 'a'));
    resolution = StatusClient::resolveSocketPath();
    QVERIFY(!resolution.acceptable);

    // Environment values cannot carry a NUL byte (getenv stops there), so the
    // defensive NUL check is verified directly against the path validator.
    QString embeddedNul = QStringLiteral("/tmp/gedefense");
    embeddedNul.append(QChar(0));
    embeddedNul.append(QStringLiteral("hidden.sock"));
    QVERIFY(!gedefense::paths::isAcceptableSocketPath(embeddedNul));
    QVERIFY(gedefense::paths::isAcceptableSocketPath(QStringLiteral("/run/gedefense/gedefense.sock")));
    QVERIFY(!gedefense::paths::isAcceptableSocketPath(QString()));
    QVERIFY(!gedefense::paths::isAcceptableSocketPath(QStringLiteral("gedefense.sock")));
}

void TestStatusClient::refusesInvalidSocketPathFromEnvironment()
{
    qputenv("GEDEFENSE_TRAY_SOCKET", QByteArray("not-absolute.sock"));

    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));

    StatusClient client(fastTimings());
    QCOMPARE(client.socketResolution().acceptable, false);
    QSignalSpy unavailableSpy(&client, &StatusClient::unavailable);

    client.start();
    QVERIFY(unavailableSpy.wait(5000));
    QCOMPARE(client.lastFailureKind(), FailureKind::InvalidSocketPath);
    QCOMPARE(daemon.connectionCount(), 0);
    client.stop();
}

void TestStatusClient::stopEndsPolling()
{
    FakeDaemon daemon;
    QVERIFY(daemon.listen(socketPath()));
    daemon.setReply(withNewline(QByteArray(kCompactReply)));

    StatusClient client(fastTimings());
    QSignalSpy updatedSpy(&client, &StatusClient::updated);
    client.start();
    QVERIFY(updatedSpy.wait(5000));
    client.stop();

    const int emissionsAfterStop = static_cast<int>(updatedSpy.count());
    const int connectionsAfterStop = daemon.connectionCount();
    QTest::qWait(400);
    QCOMPARE(static_cast<int>(updatedSpy.count()), emissionsAfterStop);
    QCOMPARE(daemon.connectionCount(), connectionsAfterStop);
    QVERIFY(!client.isRunning());
}

QTEST_GUILESS_MAIN(TestStatusClient)

#include "tst_status_client.moc"

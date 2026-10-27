// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Validation tests for the ONLY place where JSON is interpreted. Every field is
// optional and every value is treated as hostile input.
//
// All wire samples live in wire_samples.h (see the comment there: moc must not
// have to parse raw strings or escape sequences).

#include "status_payload.h"
#include "wire_samples.h"

#include <QByteArray>
#include <QTest>

using gedefense::ParseFailure;
using gedefense::StatusPayload;
using gedefense::StatusState;
using namespace gedefense::samples;

class TestStatusPayload : public QObject
{
    Q_OBJECT

private slots:
    void parsesFullPayload();
    void parsesAllStates_data();
    void parsesAllStates();
    void missingFieldsBecomeAbsent();
    void unknownKeysAreIgnored();
    void wrongTypesAreRejectedWithoutCrash();
    void rejectsNonObjectPayloads();
    void rejectsOversizedReply();
    void rejectsTruncatedJson();
    void rejectsNonJsonGarbage();
    void rejectsWrongProtocolVersion_data();
    void rejectsWrongProtocolVersion();
    void rejectsOutOfRangeCounters();
    void boundsLongStrings();
    void stripsControlAndBidiCharacters();
    void toleratesInvalidUtf8();
    void parsesActiveAlert();
    void parsesNullAndMalformedActiveAlert();
    void mapsStateKeys();
};

void TestStatusPayload::parsesFullPayload()
{
    ParseFailure failure = ParseFailure::MalformedJson;
    const auto payload = gedefense::parseStatusLine(QByteArray(kFullReply), &failure);

    QVERIFY(payload.has_value());
    QCOMPARE(failure, ParseFailure::None);
    QVERIFY(payload->valid);
    QCOMPARE(payload->state, StatusState::Secure);
    QCOMPARE(payload->statusReason, QStringLiteral("Alle Schutzschichten aktiv"));
    QCOMPARE(payload->productVersion, QStringLiteral("5.1.0-beta.1"));
    QCOMPARE(payload->nodeName, QStringLiteral("visiongaia.de"));
    QCOMPARE(payload->releasePhase, QStringLiteral("enforce"));
    QCOMPARE(payload->enforcement, QStringLiteral("enforce"));
    QCOMPARE(payload->kernelPolicy, QStringLiteral("verified-enforce"));
    QVERIFY(payload->ebpfActive.has_value());
    QCOMPARE(*payload->ebpfActive, true);
    QCOMPARE(payload->sensor, QStringLiteral("fanotify-exec+ebpf-exec+cgroup-egress+procfs-fallback"));
    QVERIFY(payload->threatCountToday.has_value());
    QCOMPARE(*payload->threatCountToday, 18LL);
    QVERIFY(payload->blockedActive.has_value());
    QCOMPARE(*payload->blockedActive, 288LL);
    QCOMPARE(payload->lastAnomalySummary, QStringLiteral("Portscan verworfen"));
    QVERIFY(payload->generatedAt.isValid());
    QVERIFY(payload->generatedAt.timeSpec() == Qt::UTC);
    QCOMPARE(payload->generatedAt.toUTC().toString(Qt::ISODate), QStringLiteral("2026-10-16T14:57:03Z"));
    QVERIFY(payload->lastAnomalyAt.isValid());
    QVERIFY(!payload->activeAlert.present);
    QVERIFY(!payload->stale);
}

void TestStatusPayload::parsesAllStates_data()
{
    QTest::addColumn<QByteArray>("line");
    QTest::addColumn<int>("expected");

    QTest::newRow("secure") << QByteArray(kStateSecure) << static_cast<int>(StatusState::Secure);
    QTest::newRow("warning") << QByteArray(kStateWarning) << static_cast<int>(StatusState::Warning);
    QTest::newRow("alert") << QByteArray(kStateAlert) << static_cast<int>(StatusState::Alert);
    QTest::newRow("stopped") << QByteArray(kStateStopped) << static_cast<int>(StatusState::Stopped);
    QTest::newRow("upper case") << QByteArray(kStateUpper) << static_cast<int>(StatusState::Secure);
    QTest::newRow("unknown value") << QByteArray(kStateUnknownValue) << static_cast<int>(StatusState::Unknown);
    QTest::newRow("missing status") << QByteArray(kStateMissing) << static_cast<int>(StatusState::Unknown);
}

void TestStatusPayload::parsesAllStates()
{
    QFETCH(QByteArray, line);
    QFETCH(int, expected);

    const auto payload = gedefense::parseStatusLine(line);
    QVERIFY(payload.has_value());
    QCOMPARE(static_cast<int>(payload->state), expected);
}

void TestStatusPayload::missingFieldsBecomeAbsent()
{
    const auto payload = gedefense::parseStatusLine(QByteArray(kStateMissing));
    QVERIFY(payload.has_value());
    QVERIFY(payload->statusReason.isEmpty());
    QVERIFY(payload->productVersion.isEmpty());
    QVERIFY(payload->nodeName.isEmpty());
    QVERIFY(payload->releasePhase.isEmpty());
    QVERIFY(payload->enforcement.isEmpty());
    QVERIFY(payload->kernelPolicy.isEmpty());
    QVERIFY(payload->sensor.isEmpty());
    QVERIFY(!payload->ebpfActive.has_value());
    QVERIFY(!payload->threatCountToday.has_value());
    QVERIFY(!payload->blockedActive.has_value());
    QVERIFY(!payload->generatedAt.isValid());
    QVERIFY(!payload->lastAnomalyAt.isValid());
    QVERIFY(payload->lastAnomalySummary.isEmpty());
    QVERIFY(!payload->activeAlert.present);
    QCOMPARE(payload->state, StatusState::Unknown);
}

void TestStatusPayload::unknownKeysAreIgnored()
{
    const auto payload = gedefense::parseStatusLine(QByteArray(kUnknownKeys));
    QVERIFY(payload.has_value());
    QCOMPARE(payload->state, StatusState::Secure);
    QVERIFY(payload->sensor.isEmpty());
}

void TestStatusPayload::wrongTypesAreRejectedWithoutCrash()
{
    const auto payload = gedefense::parseStatusLine(QByteArray(kWrongTypes));

    QVERIFY(payload.has_value());
    QCOMPARE(payload->state, StatusState::Unknown);
    QVERIFY(payload->statusReason.isEmpty());
    QVERIFY(!payload->generatedAt.isValid());
    QVERIFY(payload->productVersion.isEmpty());
    QVERIFY(payload->nodeName.isEmpty());
    QVERIFY(payload->releasePhase.isEmpty());
    QVERIFY(payload->enforcement.isEmpty());
    QVERIFY(payload->kernelPolicy.isEmpty());
    QVERIFY(!payload->ebpfActive.has_value());
    QVERIFY(payload->sensor.isEmpty());
    QVERIFY(!payload->threatCountToday.has_value());
    QVERIFY(!payload->blockedActive.has_value());
    QVERIFY(!payload->lastAnomalyAt.isValid());
    QVERIFY(payload->lastAnomalySummary.isEmpty());
    QVERIFY(!payload->activeAlert.present);
}

void TestStatusPayload::rejectsNonObjectPayloads()
{
    ParseFailure failure = ParseFailure::None;
    const auto arrayResult = gedefense::parseStatusLine(QByteArray(kNonObjectArray), &failure);
    QVERIFY(!arrayResult.has_value());
    QCOMPARE(failure, ParseFailure::NotAnObject);

    failure = ParseFailure::None;
    // Qt's JSON reader accepts only an object or an array at the top level, so a
    // bare scalar is already a parse error rather than "not an object".
    const auto stringResult = gedefense::parseStatusLine(QByteArray(kNonObjectString), &failure);
    QVERIFY(!stringResult.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);

    failure = ParseFailure::None;
    const auto emptyResult = gedefense::parseStatusLine(QByteArray(kEmpty), &failure);
    QVERIFY(!emptyResult.has_value());
    QCOMPARE(failure, ParseFailure::Empty);

    failure = ParseFailure::None;
    const auto newlineResult = gedefense::parseStatusLine(QByteArray(kNewlineOnly), &failure);
    QVERIFY(!newlineResult.has_value());
    QCOMPARE(failure, ParseFailure::Empty);
}

void TestStatusPayload::rejectsOversizedReply()
{
    QByteArray oversized = QByteArray(kBoundReplyPrefix);
    oversized.append(QByteArray(6000, 'x'));
    oversized.append(QByteArray(kBoundReplySuffix));

    ParseFailure failure = ParseFailure::None;
    const auto oversizedResult = gedefense::parseStatusLine(oversized, &failure);
    QVERIFY(!oversizedResult.has_value());
    QCOMPARE(failure, ParseFailure::TooLarge);

    // Exactly at the bound: the content is still inspected.
    QByteArray atBound = QByteArray(kBoundReplyPrefix);
    const int filler = gedefense::kMaximumReplyBytes - static_cast<int>(atBound.size())
        - static_cast<int>(QByteArray(kBoundReplySuffix).size());
    atBound.append(QByteArray(filler, 'y'));
    atBound.append(QByteArray(kBoundReplySuffix));
    QCOMPARE(atBound.size(), gedefense::kMaximumReplyBytes);
    QVERIFY(gedefense::parseStatusLine(atBound).has_value());
}

void TestStatusPayload::rejectsTruncatedJson()
{
    ParseFailure failure = ParseFailure::None;
    const auto truncated = gedefense::parseStatusLine(QByteArray(kTruncatedReply), &failure);
    QVERIFY(!truncated.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);

    failure = ParseFailure::None;
    const auto unterminated = gedefense::parseStatusLine(QByteArray(kUnterminatedReply), &failure);
    QVERIFY(!unterminated.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);
}

void TestStatusPayload::rejectsNonJsonGarbage()
{
    ParseFailure failure = ParseFailure::None;
    const auto text = gedefense::parseStatusLine(QByteArray(kGarbageText), &failure);
    QVERIFY(!text.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);

    failure = ParseFailure::None;
    const auto html = gedefense::parseStatusLine(QByteArray(kGarbageHtml), &failure);
    QVERIFY(!html.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);

    failure = ParseFailure::None;
    const auto binary = gedefense::parseStatusLine(binaryGarbage(), &failure);
    QVERIFY(!binary.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);

    failure = ParseFailure::None;
    const auto trailing = gedefense::parseStatusLine(QByteArray(kGarbageTrailing), &failure);
    QVERIFY(!trailing.has_value());
    QCOMPARE(failure, ParseFailure::MalformedJson);
}

void TestStatusPayload::rejectsWrongProtocolVersion_data()
{
    QTest::addColumn<QByteArray>("line");
    QTest::addColumn<int>("expected");

    QTest::newRow("missing") << QByteArray(kVersionMissing) << static_cast<int>(ParseFailure::VersionMissing);
    QTest::newRow("string") << QByteArray(kVersionString) << static_cast<int>(ParseFailure::VersionMissing);
    QTest::newRow("null") << QByteArray(kVersionNull) << static_cast<int>(ParseFailure::VersionMissing);
    QTest::newRow("future") << QByteArray(kVersionFuture) << static_cast<int>(ParseFailure::VersionUnsupported);
    QTest::newRow("fraction") << QByteArray(kVersionFraction) << static_cast<int>(ParseFailure::VersionUnsupported);
    QTest::newRow("zero") << QByteArray(kVersionZero) << static_cast<int>(ParseFailure::VersionUnsupported);
}

void TestStatusPayload::rejectsWrongProtocolVersion()
{
    QFETCH(QByteArray, line);
    QFETCH(int, expected);

    ParseFailure failure = ParseFailure::None;
    const auto payload = gedefense::parseStatusLine(line, &failure);
    QVERIFY(!payload.has_value());
    QCOMPARE(static_cast<int>(failure), expected);
}

void TestStatusPayload::rejectsOutOfRangeCounters()
{
    const auto payload = gedefense::parseStatusLine(QByteArray(kCountersInvalid));
    QVERIFY(payload.has_value());
    QVERIFY(!payload->threatCountToday.has_value());
    QVERIFY(!payload->blockedActive.has_value());

    const auto huge = gedefense::parseStatusLine(QByteArray(kCountersHuge));
    QVERIFY(huge.has_value());
    QVERIFY(!huge->threatCountToday.has_value());

    const auto boundary = gedefense::parseStatusLine(QByteArray(kCountersBoundary));
    QVERIFY(boundary.has_value());
    QVERIFY(boundary->blockedActive.has_value());
    QVERIFY(boundary->threatCountToday.has_value());
    QCOMPARE(*boundary->blockedActive, 0LL);
    QCOMPARE(*boundary->threatCountToday, 999999999999LL);
}

void TestStatusPayload::boundsLongStrings()
{
    QByteArray line = QByteArray(kLongReasonPrefix);
    line.append(QByteArray(900, 'a'));
    line.append(QByteArray(kLongReasonSuffix));

    const auto payload = gedefense::parseStatusLine(line);
    QVERIFY(payload.has_value());
    QCOMPARE(payload->state, StatusState::Warning);
    QCOMPARE(payload->statusReason.size(), gedefense::kMaximumTextFieldLength + 1);
    QVERIFY(payload->statusReason.endsWith(QChar(0x2026)));
}

void TestStatusPayload::stripsControlAndBidiCharacters()
{
    const auto payload = gedefense::parseStatusLine(QByteArray(kControlCharacters));

    QVERIFY(payload.has_value());
    // Newlines, tabs, bells and the right-to-left override are removed so that
    // no untrusted text can restructure or spoof the interface. Markup is kept
    // verbatim: the payload layer never interprets it, and the view renders
    // plain text only.
    QCOMPARE(payload->statusReason, QStringLiteral("Zeile1Zeile2<u>markup</u>evil"));
    QVERIFY(!payload->statusReason.contains(QChar(0x202E)));
    QVERIFY(!payload->statusReason.contains(QLatin1Char('\n')));
    QVERIFY(!payload->statusReason.contains(QLatin1Char('\t')));
}

void TestStatusPayload::toleratesInvalidUtf8()
{
    QByteArray line = QByteArray(kInvalidUtf8Prefix);
    line.append(static_cast<char>(0xFF));
    line.append(static_cast<char>(0xFE));
    line.append(QByteArray(kInvalidUtf8Suffix));

    // Either the reply is rejected as malformed or the invalid bytes are
    // replaced. In both cases nothing may crash and no raw byte may reach a
    // label unchanged.
    const auto payload = gedefense::parseStatusLine(line);
    if (payload.has_value())
    {
        QVERIFY(payload->nodeName.size() <= gedefense::kMaximumShortFieldLength + 1);
        for (const QChar character : payload->nodeName)
        {
            QVERIFY(character.category() != QChar::Other_Control);
            QVERIFY(character.category() != QChar::Other_Format);
        }
    }
    QVERIFY(true);
}

void TestStatusPayload::parsesActiveAlert()
{
    const auto payload = gedefense::parseStatusLine(QByteArray(kAlertFull));

    QVERIFY(payload.has_value());
    QCOMPARE(payload->state, StatusState::Alert);
    QVERIFY(payload->activeAlert.present);
    QCOMPARE(payload->activeAlert.summary, QStringLiteral("Portscan verworfen"));
    QCOMPARE(payload->activeAlert.severity, QStringLiteral("high"));
    QCOMPARE(payload->activeAlert.target, QStringLiteral("10.0.0.4"));
    QVERIFY(payload->activeAlert.since.isValid());
}

void TestStatusPayload::parsesNullAndMalformedActiveAlert()
{
    const auto nullAlert = gedefense::parseStatusLine(QByteArray(kAlertNull));
    QVERIFY(nullAlert.has_value());
    QVERIFY(!nullAlert->activeAlert.present);

    const auto partial = gedefense::parseStatusLine(QByteArray(kAlertPartial));
    QVERIFY(partial.has_value());
    QVERIFY(partial->activeAlert.present);
    QVERIFY(partial->activeAlert.severity.isEmpty());
    QVERIFY(partial->activeAlert.summary.isEmpty());
    QVERIFY(!partial->activeAlert.since.isValid());

    const auto badTimestamp = gedefense::parseStatusLine(QByteArray(kAlertBadTimestamp));
    QVERIFY(badTimestamp.has_value());
    QVERIFY(!badTimestamp->activeAlert.since.isValid());

    const auto badType = gedefense::parseStatusLine(QByteArray(kAlertBadType));
    QVERIFY(badType.has_value());
    QVERIFY(!badType->activeAlert.present);
}

void TestStatusPayload::mapsStateKeys()
{
    QCOMPARE(gedefense::statusStateKey(StatusState::Secure), QStringLiteral("secure"));
    QCOMPARE(gedefense::statusStateKey(StatusState::Warning), QStringLiteral("warning"));
    QCOMPARE(gedefense::statusStateKey(StatusState::Alert), QStringLiteral("alert"));
    QCOMPARE(gedefense::statusStateKey(StatusState::Stopped), QStringLiteral("stopped"));
    QCOMPARE(gedefense::statusStateKey(StatusState::Unknown), QStringLiteral("unknown"));
}

QTEST_GUILESS_MAIN(TestStatusPayload)

#include "tst_status_payload.moc"

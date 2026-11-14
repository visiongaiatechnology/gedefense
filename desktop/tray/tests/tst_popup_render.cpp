// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Offscreen render harness: writes one PNG per state (plus the stress variants:
// stale data, very long German compounds, constrained viewport and a disabled
// console action) so that the composition can be reviewed visually without a
// desktop session.
//
// Usage: tst_popup_render [--out <directory>]
// Without --out the compile-time path build/screenshots is used.
//
// The same harness also proves that untrusted control-plane payloads cannot
// inject rich text into the tray UI (FIND-032): tooltips are rich-text sinks in
// Qt, so the payload cases `<b>`, `<img src=...>` and `<a href=...>` must appear
// as literal text, both in the flyout and in the tray icon tooltip.

#include "state_icons.h"
#include "state_labels.h"
#include "status_client.h"
#include "status_payload.h"
#include "status_popup.h"
#include "theme.h"
#include "tray_controller.h"
#include "ui_text.h"

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QImage>
#include <QLabel>
#include <QList>
#include <QPixmap>
#include <QRect>
#include <QSet>
#include <QSizeF>
#include <QString>
#include <QSystemTrayIcon>
#include <QTest>
#include <QTextDocument>

using gedefense::ActiveAlert;
using gedefense::StatusPayload;
using gedefense::StatusPopup;
using gedefense::StatusState;

namespace {

QString g_outputDirectory;

constexpr int kMinimumScreenshotEdge = 180;

// The soft-break helper inserts zero-width spaces for the *displayed* elided
// text only; they are stripped again when a test compares against the payload.
constexpr ushort kZeroWidthSpace = 0x200B;

// Renders a rich-text sink string exactly as Qt renders it and returns the
// literal text the user sees. An injected element disappears into formatting
// (an <img> even becomes U+FFFC), while an escaped payload comes back verbatim.
QString renderedPlainText(const QString& richText)
{
    QTextDocument document;
    document.setHtml(richText);
    QString text = document.toPlainText();
    text.replace(QChar(QChar::LineSeparator), QLatin1Char('\n'));
    text.replace(QChar(QChar::ParagraphSeparator), QLatin1Char('\n'));
    return text;
}

// The markup an unescaped control-plane payload could smuggle into a rich-text
// sink. The explicit <p>/<br/> framing of ui_text::plainTooltipText is allowed,
// every element from the payload is not.
bool containsInjectedMarkup(const QString& text)
{
    return text.contains(QStringLiteral("<b>")) || text.contains(QStringLiteral("<img"))
        || text.contains(QStringLiteral("<a href")) || text.contains(QStringLiteral("<script"))
        || text.contains(QStringLiteral("<p style"));
}

QDateTime timestamp(int year, int month, int day, int hour, int minute, int second)
{
    return QDateTime(QDate(year, month, day), QTime(hour, minute, second), Qt::UTC);
}

StatusPayload basePayload(StatusState state, const QString& reason)
{
    StatusPayload payload;
    payload.valid = true;
    payload.state = state;
    payload.statusReason = reason;
    payload.generatedAt = timestamp(2026, 10, 16, 14, 57, 3);
    payload.productVersion = QStringLiteral("5.1.0-beta.2");
    payload.nodeName = QStringLiteral("visiongaia.de");
    payload.releasePhase = QStringLiteral("enforce");
    payload.enforcement = QStringLiteral("enforce");
    payload.kernelPolicy = QStringLiteral("verified-enforce");
    payload.ebpfActive = true;
    payload.sensor = QStringLiteral("fanotify-exec+ebpf-exec+cgroup-egress+procfs-fallback");
    payload.threatCountToday = 18;
    payload.blockedActive = 288;
    payload.lastAnomalyAt = timestamp(2026, 10, 16, 14, 15, 0);
    payload.lastAnomalySummary = QStringLiteral("Portscan verworfen");
    return payload;
}

StatusPayload payloadForState(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return basePayload(state, QStringLiteral("Alle Schutzschichten aktiv und verifiziert."));
    case StatusState::Warning:
    {
        StatusPayload payload
            = basePayload(state,
                          QStringLiteral("Die Kernel-Policy wird im Übergangsmodus durchgesetzt."));
        payload.ebpfActive = true;
        payload.sensor = QStringLiteral("fanotify-exec+procfs-fallback");
        return payload;
    }
    case StatusState::Alert:
    {
        StatusPayload payload = basePayload(state, QStringLiteral("Aktive Bedrohung erkannt und blockiert."));
        payload.activeAlert = ActiveAlert{true,
                                          QStringLiteral("Portscan verworfen"),
                                          QStringLiteral("high"),
                                          QStringLiteral("10.0.0.4"),
                                          timestamp(2026, 10, 16, 14, 15, 0)};
        return payload;
    }
    case StatusState::Stopped:
    case StatusState::Unknown:
        break;
    }
    return basePayload(StatusState::Unknown, QString());
}

} // namespace

class TestStatusPopupRender : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void bundledSvgResourcesAreAvailable();
    void stateSilhouettesAreDistinct();
    void rendersSecureState();
    void rendersWarningState();
    void rendersAlertState();
    void rendersStoppedState();
    void rendersStaleStoppedState();
    void rendersLongGermanCompounds();
    void rendersConstrainedViewport();
    void rendersDisabledConsoleAction();

    // FIND-032 regression: untrusted control-plane payloads must render as
    // literal text in every rich-text sink (tooltips, notifications).
    void plainTooltipTextEscapesInjectedPayload_data();
    void plainTooltipTextEscapesInjectedPayload();
    void popupRendersInjectedPayloadAsLiteralText_data();
    void popupRendersInjectedPayloadAsLiteralText();
    void trayTooltipRendersInjectedPayloadAsLiteralText();
    void notificationBodyEscapesInjectedPayload();

private:
    // QVERIFY can only be used in void functions, therefore the path of the
    // rendered file is reported through a member.
    void renderAndCheck(StatusPopup& popup,
                        const QString& fileName,
                        const QRect& trayGeometry,
                        const QRect& availableGeometry,
                        const QSize& maximumSize);

    QString m_lastScreenshotPath;
};

void TestStatusPopupRender::initTestCase()
{
    Q_INIT_RESOURCE(gedefense_tray);
    QVERIFY2(!g_outputDirectory.isEmpty(), "no output directory configured");
    QVERIFY2(QDir().mkpath(g_outputDirectory),
             qPrintable(QStringLiteral("cannot create %1").arg(g_outputDirectory)));
}

// The icons must come from the bundled SVGs, not from the painted placeholder
// in state_icons.cpp (which is only a defensive fallback).
void TestStatusPopupRender::bundledSvgResourcesAreAvailable()
{
    const StatusState states[] = {StatusState::Secure,
                                 StatusState::Warning,
                                 StatusState::Alert,
                                 StatusState::Stopped};
    for (const StatusState state : states)
    {
        const QString resource = gedefense::labels::stateIconResource(state);
        QVERIFY2(QFile::exists(resource), qUtf8Printable(resource));
        QFile file(resource);
        QVERIFY(file.open(QIODevice::ReadOnly));
        const QByteArray content = file.readAll();
        QVERIFY(content.size() > 200);
        QVERIFY(content.startsWith("<?xml"));
    }
}

// Four distinct silhouettes: no state may be signalled by colour alone.
void TestStatusPopupRender::stateSilhouettesAreDistinct()
{
    const StatusState states[] = {StatusState::Secure,
                                 StatusState::Warning,
                                 StatusState::Alert,
                                 StatusState::Stopped};
    QList<QImage> images;
    for (const StatusState state : states)
    {
        const QPixmap pixmap = gedefense::icons::pixmap(state, gedefense::theme::kIconSizePx, 1.0);
        QVERIFY(!pixmap.isNull());
        images.append(pixmap.toImage());
    }
    for (qsizetype first = 0; first < images.size(); ++first)
    {
        for (qsizetype second = first + 1; second < images.size(); ++second)
        {
            QVERIFY2(images.at(first) != images.at(second), "two states share the same silhouette");
        }
    }
}

void TestStatusPopupRender::renderAndCheck(StatusPopup& popup,
                                           const QString& fileName,
                                           const QRect& trayGeometry,
                                           const QRect& availableGeometry,
                                           const QSize& maximumSize)
{
    popup.presentAbove(trayGeometry, availableGeometry);
    QApplication::processEvents();
    QVERIFY(popup.isPresented());

    const QPixmap shot = popup.grab();
    QVERIFY(!shot.isNull());
    // Logical sizes are compared: with QT_SCALE_FACTOR the pixmap is rendered at
    // the device pixel ratio while the composition stays in logical units.
    const QSizeF logicalSize = shot.deviceIndependentSize();
    QVERIFY(logicalSize.width() >= kMinimumScreenshotEdge);
    QVERIFY(logicalSize.height() >= kMinimumScreenshotEdge / 2);
    QVERIFY(logicalSize.width() <= static_cast<qreal>(maximumSize.width()));
    QVERIFY(logicalSize.height() <= static_cast<qreal>(maximumSize.height()));

    // The render must contain real structure: background, frame, text and the
    // state silhouette produce several distinct colours.
    const QImage image = shot.toImage();
    QSet<QRgb> sampledColors;
    for (int y = 0; y < image.height(); y += 5)
    {
        for (int x = 0; x < image.width(); x += 5)
        {
            sampledColors.insert(image.pixel(x, y));
        }
    }
    QVERIFY2(sampledColors.size() >= 3, "screenshot looks blank");

    const QString path = QDir(g_outputDirectory).filePath(fileName);
    QVERIFY2(shot.save(path, "PNG"), qPrintable(QStringLiteral("cannot write %1").arg(path)));
    const QFileInfo info(path);
    QVERIFY(info.exists());
    QVERIFY(info.size() > 0);
    m_lastScreenshotPath = path;
    popup.dismiss();
}

void TestStatusPopupRender::rendersSecureState()
{
    StatusPopup popup(QCoreApplication::applicationFilePath());
    popup.applyPayload(payloadForState(StatusState::Secure));
    popup.setDataAge(900);
    renderAndCheck(popup,
                   QStringLiteral("01-secure.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 600));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

void TestStatusPopupRender::rendersWarningState()
{
    StatusPopup popup(QCoreApplication::applicationFilePath());
    popup.applyPayload(payloadForState(StatusState::Warning));
    popup.setDataAge(1200);
    renderAndCheck(popup,
                   QStringLiteral("02-warning.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 600));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

void TestStatusPopupRender::rendersAlertState()
{
    StatusPopup popup(QCoreApplication::applicationFilePath());
    popup.applyPayload(payloadForState(StatusState::Alert));
    popup.setDataAge(1500);
    renderAndCheck(popup,
                   QStringLiteral("03-alert.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 620));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

void TestStatusPopupRender::rendersStoppedState()
{
    StatusPopup popup(QCoreApplication::applicationFilePath());
    popup.applyUnavailable(QStringLiteral("Der GeDefense-Dienst ist nicht erreichbar."));
    popup.setDataAge(-1);
    renderAndCheck(popup,
                   QStringLiteral("04-stopped.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 600));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

void TestStatusPopupRender::rendersStaleStoppedState()
{
    StatusPopup popup(QCoreApplication::applicationFilePath());
    StatusPayload payload = payloadForState(StatusState::Secure);
    payload.stale = true;
    popup.applyPayload(payload);
    popup.applyUnavailable(QStringLiteral("Der GeDefense-Dienst antwortet nicht mehr."));
    popup.setDataAge(23000);
    renderAndCheck(popup,
                   QStringLiteral("05-stopped-stale.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 620));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

void TestStatusPopupRender::rendersLongGermanCompounds()
{
    StatusPopup popup(QCoreApplication::applicationFilePath());
    StatusPayload payload = payloadForState(StatusState::Alert);
    payload.statusReason = QStringLiteral(
        "Datenverkehrsüberwachungsausnahmegenehmigung: Die Protokollierung der "
        "Netzwerkverbindungsprotokollierungskonfiguration wurde für die "
        "Sicherheitsrichtlinienübergangsphase ausgesetzt.");
    payload.nodeName = QStringLiteral(
        "produktionsdatenbankreplikationsserver.unternehmensnetzwerk.visiongaia.de");
    payload.sensor = QStringLiteral(
        "fanotify-exec+ebpf-exec+cgroup-egress+procfs-fallback+netfilter-queue+audit-fallback");
    payload.activeAlert.summary = QStringLiteral(
        "Verschlüsselungsverhandlungsschwachstellenausnutzungsversuch");
    payload.activeAlert.severity = QStringLiteral("kritisch");
    payload.activeAlert.target = QStringLiteral(
        "aussenstellenanbindungsschnittstellenkonzentrator.visiongaia.de");
    payload.lastAnomalySummary = QStringLiteral(
        "Netzwerksegmentierungsrichtlinienverletzungsdurchsatzanomalie");
    popup.applyPayload(payload);
    popup.setDataAge(2000);

    renderAndCheck(popup,
                   QStringLiteral("06-long-german-compounds.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 700));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

void TestStatusPopupRender::rendersConstrainedViewport()
{
    // A deliberately small available area (for example a scaled session on a
    // small panel): the panel must shrink and scroll instead of leaving the
    // screen.
    StatusPopup popup(QCoreApplication::applicationFilePath());
    popup.applyPayload(payloadForState(StatusState::Alert));

    const QRect tray(380, 270, 24, 24);
    const QRect available(0, 0, 420, 300);
    renderAndCheck(popup,
                   QStringLiteral("07-constrained-viewport.png"),
                   tray,
                   available,
                   QSize(available.width(), available.height()));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));

    const QRect geometry = popup.geometry();
    QVERIFY2(geometry.left() >= available.left(), "panel left of the screen");
    QVERIFY2(geometry.top() >= available.top(), "panel above the screen");
}

void TestStatusPopupRender::rendersDisabledConsoleAction()
{
    // The console action is disabled (not hidden) when the binary is missing.
    StatusPopup popup(QStringLiteral("/nonexistent/gedefense-app"));
    popup.applyPayload(payloadForState(StatusState::Secure));
    popup.setDataAge(1000);
    renderAndCheck(popup,
                   QStringLiteral("08-console-action-disabled.png"),
                   QRect(1860, 1046, 24, 24),
                   QRect(0, 0, 1920, 1080),
                   QSize(gedefense::theme::kPanelWidthPreferred, 600));
    QVERIFY(QFileInfo::exists(m_lastScreenshotPath));
}

// ---------------------------------------------------------------------------
// FIND-032 - Qt tooltips and notifications are rich-text sinks. The control
// plane sends only length/control-character sanitised strings (status_payload.cpp),
// so a payload such as `<b>`, `<img src=...>` or `<a href=...>` must stay
// literal text instead of becoming markup in the tray UI.
// ---------------------------------------------------------------------------

void TestStatusPopupRender::plainTooltipTextEscapesInjectedPayload_data()
{
    QTest::addColumn<QString>("payload");

    QTest::newRow("bold") << QStringLiteral("<b>Schutz aktiv</b>");
    QTest::newRow("image") << QStringLiteral("<img src=\"file:///etc/passwd\">");
    QTest::newRow("link") << QStringLiteral("<a href=\"https://example.invalid\">Jetzt prüfen</a>");
    QTest::newRow("paragraph") << QStringLiteral("<p style=\"color:red\">Warnung</p>");
    QTest::newRow("entity") << QStringLiteral("&lt;b&gt;");
}

void TestStatusPopupRender::plainTooltipTextEscapesInjectedPayload()
{
    QFETCH(QString, payload);

    const QString tooltip = gedefense::ui_text::plainTooltipText(payload);

    // The framing is ours; the payload itself is not part of the markup and must
    // not match any injected element.
    QVERIFY2(Qt::mightBeRichText(tooltip), qUtf8Printable(tooltip));
    QVERIFY(tooltip.startsWith(QStringLiteral("<p>")));
    QVERIFY(tooltip.endsWith(QStringLiteral("</p>")));
    QVERIFY2(!tooltip.contains(payload), qUtf8Printable(tooltip));
    QVERIFY2(!containsInjectedMarkup(tooltip), qUtf8Printable(tooltip));

    // Proof of literal plaintext behaviour: Qt's rich-text renderer returns the
    // payload verbatim - no formatting, no image object, no link.
    QCOMPARE(renderedPlainText(tooltip), payload);
}

void TestStatusPopupRender::popupRendersInjectedPayloadAsLiteralText_data()
{
    QTest::addColumn<QString>("payload");

    QTest::newRow("bold") << QStringLiteral("<b>Schutz aktiv</b>");
    QTest::newRow("image") << QStringLiteral("<img src=\"file:///etc/passwd\">");
    QTest::newRow("link") << QStringLiteral("<a href=\"https://example.invalid\">Jetzt prüfen</a>");
}

void TestStatusPopupRender::popupRendersInjectedPayloadAsLiteralText()
{
    QFETCH(QString, payload);

    StatusPopup popup(QStringLiteral("/nonexistent/gedefense-app"));
    StatusPayload data = payloadForState(StatusState::Alert);
    data.productVersion = payload;
    data.nodeName = payload;
    data.statusReason = payload;
    data.sensor = payload;
    data.lastAnomalySummary = payload;
    data.activeAlert.summary = payload;
    data.activeAlert.severity = payload;
    data.activeAlert.target = payload;
    popup.applyPayload(data);

    // 1) The visible plain-text widgets render the markup characters literally.
    QLabel* reason = popup.findChild<QLabel*>(QStringLiteral("reasonLabel"));
    QVERIFY(reason != nullptr);
    QCOMPARE(reason->textFormat(), Qt::PlainText);
    QString reasonText = reason->text();
    reasonText.remove(QChar(kZeroWidthSpace));
    QCOMPARE(reasonText, payload);

    QLabel* alertMeta = popup.findChild<QLabel*>(QStringLiteral("alertMeta"));
    QVERIFY(alertMeta != nullptr);
    QCOMPARE(alertMeta->textFormat(), Qt::PlainText);
    QString alertMetaText = alertMeta->text();
    alertMetaText.remove(QChar(kZeroWidthSpace));
    QVERIFY2(alertMetaText.contains(payload), qUtf8Printable(alertMetaText));

    // 2) Every tooltip of the flyout is escaped and renders the payload verbatim.
    const QList<QLabel*> labels = popup.findChildren<QLabel*>();
    int affectedTooltips = 0;
    for (QLabel* label : labels)
    {
        const QString tooltip = label->toolTip();
        if (tooltip.isEmpty())
        {
            continue;
        }
        QVERIFY2(Qt::mightBeRichText(tooltip), qUtf8Printable(tooltip));
        QVERIFY2(!containsInjectedMarkup(tooltip), qUtf8Printable(tooltip));
        const QString rendered = renderedPlainText(tooltip);
        QVERIFY2(!rendered.contains(QChar(QChar::ObjectReplacementCharacter)), qUtf8Printable(rendered));
        if (rendered.contains(payload))
        {
            ++affectedTooltips;
        }
    }
    QVERIFY2(affectedTooltips >= 3, "the injected payload did not reach the tooltip sinks");

    QLabel* headerMeta = popup.findChild<QLabel*>(QStringLiteral("headerMeta"));
    QVERIFY(headerMeta != nullptr);
    QCOMPARE(renderedPlainText(headerMeta->toolTip()), QStringLiteral("v%1 · %2").arg(payload, payload));
}

void TestStatusPopupRender::trayTooltipRendersInjectedPayloadAsLiteralText()
{
    StatusPopup popup(QStringLiteral("/nonexistent/gedefense-app"));
    gedefense::StatusClient client;
    gedefense::TrayController controller(&client, &popup);

    const QString payload
        = QStringLiteral("<img src=\"file:///etc/passwd\"> <a href=\"https://example.invalid\">prüfen</a>");
    // StatusClient::unavailable is a signal and therefore a public method: the
    // client-defined failure is emitted directly so the test does not depend on
    // socket timing.
    client.unavailable(payload);

    QSystemTrayIcon* tray = controller.trayIcon();
    QVERIFY(tray != nullptr);
    QCOMPARE(controller.currentState(), StatusState::Stopped);

    const QString tooltip = tray->toolTip();
    QVERIFY(!tooltip.isEmpty());
    QVERIFY2(Qt::mightBeRichText(tooltip), qUtf8Printable(tooltip));
    QVERIFY2(!containsInjectedMarkup(tooltip), qUtf8Printable(tooltip));
    QVERIFY2(!tooltip.contains(payload), qUtf8Printable(tooltip));
    const QString rendered = renderedPlainText(tooltip);
    QVERIFY2(rendered.contains(payload), qUtf8Printable(rendered));
    QVERIFY2(!rendered.contains(QChar(QChar::ObjectReplacementCharacter)), qUtf8Printable(rendered));
}

void TestStatusPopupRender::notificationBodyEscapesInjectedPayload()
{
    const QString payload
        = QStringLiteral("<b>Vertrauen</b> <a href=\"https://example.invalid\">Jetzt scannen</a>");
    const QString body = gedefense::ui_text::plainNotificationText(payload);

    QVERIFY2(!containsInjectedMarkup(body), qUtf8Printable(body));
    QCOMPARE(body, payload.toHtmlEscaped());
    // A markup-capable notification server decodes the entities back to the
    // literal payload; a plain-text server shows the escaped characters. Neither
    // can produce an injected element.
    QCOMPARE(renderedPlainText(body), payload);
}

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("tst_popup_render"));
    application.setStyleSheet(gedefense::theme::styleSheet());

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Renders the GeDefense status flyout offscreen."));
    parser.addHelpOption();
    const QCommandLineOption outputOption(QStringList{QStringLiteral("o"), QStringLiteral("out")},
                                          QStringLiteral("Directory for the rendered PNG files."),
                                          QStringLiteral("directory"));
    parser.addOption(outputOption);
    parser.parse(application.arguments());
    if (parser.isSet(QStringLiteral("help")))
    {
        parser.showHelp(0);
    }

    g_outputDirectory = parser.isSet(outputOption) ? parser.value(outputOption)
                                                   : QStringLiteral(GEDEFENSE_SCREENSHOT_DIR);

    // QTest receives a pristine command line: the screenshot options are parsed
    // by the application above.
    TestStatusPopupRender test;
    return QTest::qExec(&test, 1, argv);
}

#include "tst_popup_render.moc"

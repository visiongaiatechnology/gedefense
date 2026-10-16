// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include "status_popup.h"

#include "app_paths.h"
#include "state_icons.h"
#include "state_labels.h"
#include "theme.h"

#include <QEvent>
#include <QFileInfo>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLocale>
#include <QProcess>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QShowEvent>
#include <QSizePolicy>
#include <QStringList>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>

namespace gedefense {
namespace {

constexpr int kRefreshWatchdogMs = 3000;
constexpr int kSoftBreakRunLength = 24;
constexpr int kButtonHorizontalPadding = 12;
constexpr int kButtonBorderWidth = 1;
constexpr int kButtonMinimumHeight = 32;
constexpr ushort kZeroWidthSpace = 0x200B;

void repolish(QWidget* widget)
{
    if (widget == nullptr)
    {
        return;
    }
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}

int clampValue(int value, int lower, int upper)
{
    if (upper < lower)
    {
        return lower;
    }
    return std::max(lower, std::min(value, upper));
}

QFrame* createSeparator(QWidget* parent)
{
    auto* separator = new QFrame(parent);
    separator->setObjectName(QStringLiteral("sectionSeparator"));
    separator->setFrameShape(QFrame::NoFrame);
    separator->setFixedHeight(1);
    separator->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    return separator;
}

} // namespace

// ---------------------------------------------------------------------------
// Bounded, plain-text label. The full text lives in the tooltip and the
// displayed text is elided to the actual width, so long German compounds and
// long node names can never force the panel off the screen.
// ---------------------------------------------------------------------------
class ElidedLabel final : public QLabel
{
public:
    explicit ElidedLabel(QWidget* parent = nullptr)
        : QLabel(parent)
    {
        setTextFormat(Qt::PlainText);
        setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        setMinimumWidth(0);
    }

    void setFullText(const QString& text)
    {
        m_fullText = text;
        setToolTip(text);
        applyElision();
    }

    QString fullText() const
    {
        return m_fullText;
    }

protected:
    void resizeEvent(QResizeEvent* event) override
    {
        QLabel::resizeEvent(event);
        applyElision();
    }

    void showEvent(QShowEvent* event) override
    {
        QLabel::showEvent(event);
        applyElision();
    }

    void changeEvent(QEvent* event) override
    {
        QLabel::changeEvent(event);
        if (event->type() == QEvent::FontChange || event->type() == QEvent::StyleChange)
        {
            applyElision();
        }
    }

private:
    void applyElision()
    {
        const int available = width();
        if (available <= 0)
        {
            QLabel::setText(m_fullText);
            return;
        }
        const QFontMetrics metrics(font());
        QLabel::setText(metrics.elidedText(m_fullText, Qt::ElideRight, available));
    }

    QString m_fullText;
};

StatusPopup::StatusPopup(QWidget* parent)
    : StatusPopup(QString::fromLatin1(paths::kConsoleBinaryPath), parent)
{
}

StatusPopup::StatusPopup(const QString& consoleBinaryPath, QWidget* parent)
    : QWidget(parent, Qt::Popup | Qt::FramelessWindowHint)
    , m_consoleBinaryPath(consoleBinaryPath)
{
    setObjectName(QStringLiteral("gedefenseTrayPopup"));
    setAttribute(Qt::WA_TranslucentBackground, true);
    setAttribute(Qt::WA_NoSystemBackground, true);
    setFocusPolicy(Qt::StrongFocus);

    m_refreshSafetyTimer = new QTimer(this);
    m_refreshSafetyTimer->setSingleShot(true);
    connect(m_refreshSafetyTimer, &QTimer::timeout, this, [this]() { setRefreshPending(false); });

    buildUi();
    applyStyle();
    retranslate();
    updateFromState();
}

StatusPopup::~StatusPopup() = default;

void StatusPopup::buildUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    m_panel = new QFrame(this);
    m_panel->setObjectName(QStringLiteral("panelFrame"));
    rootLayout->addWidget(m_panel);

    auto* panelLayout = new QVBoxLayout(m_panel);
    panelLayout->setContentsMargins(1, 1, 1, 1);
    panelLayout->setSpacing(0);

    // --- header: state silhouette, product line, badge -----------------------
    m_header = new QFrame(m_panel);
    m_header->setObjectName(QStringLiteral("headerBar"));
    // The header and the footer never give up space: all compression and all
    // growth is absorbed by the scrollable body.
    m_header->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    auto* headerLayout = new QHBoxLayout(m_header);
    headerLayout->setContentsMargins(theme::kSpaceLg, theme::kSpaceMd, theme::kSpaceLg, theme::kSpaceMd);
    headerLayout->setSpacing(theme::kSpaceMd);

    m_stateIcon = new QLabel(m_header);
    m_stateIcon->setObjectName(QStringLiteral("stateIcon"));
    m_stateIcon->setFixedSize(theme::kIconSizePx, theme::kIconSizePx);
    m_stateIcon->setAlignment(Qt::AlignCenter);

    auto* titleColumn = new QVBoxLayout();
    titleColumn->setContentsMargins(0, 0, 0, 0);
    titleColumn->setSpacing(2);

    m_title = new QLabel(m_header);
    m_title->setObjectName(QStringLiteral("headerTitle"));
    m_title->setFont(theme::titleFont());
    m_title->setTextFormat(Qt::PlainText);

    m_headerMeta = new ElidedLabel(m_header);
    m_headerMeta->setObjectName(QStringLiteral("headerMeta"));
    m_headerMeta->setFont(theme::technicalFont());

    titleColumn->addWidget(m_title);
    titleColumn->addWidget(m_headerMeta);

    m_badge = new QLabel(m_header);
    m_badge->setObjectName(QStringLiteral("stateBadge"));
    m_badge->setFont(theme::technicalFont());
    m_badge->setTextFormat(Qt::PlainText);
    m_badge->setAlignment(Qt::AlignCenter);
    m_badge->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

    headerLayout->addWidget(m_stateIcon, 0, Qt::AlignTop);
    headerLayout->addLayout(titleColumn, 1);
    headerLayout->addWidget(m_badge, 0, Qt::AlignTop);
    panelLayout->addWidget(m_header);

    // --- body (scrollable when the screen is short) -------------------------
    m_bodyScroll = new QScrollArea(m_panel);
    m_bodyScroll->setObjectName(QStringLiteral("bodyScroll"));
    m_bodyScroll->setWidgetResizable(true);
    m_bodyScroll->setFrameShape(QFrame::NoFrame);
    m_bodyScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_bodyScroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_bodyScroll->setFocusPolicy(Qt::StrongFocus);
    m_bodyScroll->setMinimumHeight(theme::kBodyMinimumHeightPx);

    m_body = new QWidget();
    m_body->setObjectName(QStringLiteral("bodyViewport"));
    m_bodyScroll->setWidget(m_body);

    auto* bodyLayout = new QVBoxLayout(m_body);
    bodyLayout->setContentsMargins(theme::kSpaceLg, theme::kSpaceMd, theme::kSpaceLg, theme::kSpaceMd);
    bodyLayout->setSpacing(theme::kSpaceMd);

    m_reason = new QLabel(m_body);
    m_reason->setObjectName(QStringLiteral("reasonLabel"));
    m_reason->setFont(theme::bodyFont());
    m_reason->setTextFormat(Qt::PlainText);
    m_reason->setWordWrap(true);
    m_reason->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    bodyLayout->addWidget(m_reason);

    m_alertBlock = new QFrame(m_body);
    m_alertBlock->setObjectName(QStringLiteral("alertBlock"));
    auto* alertLayout = new QVBoxLayout(m_alertBlock);
    alertLayout->setContentsMargins(theme::kSpaceMd, 0, 0, 0);
    alertLayout->setSpacing(theme::kSpaceXs);

    m_alertTitle = new QLabel(m_alertBlock);
    m_alertTitle->setObjectName(QStringLiteral("alertTitle"));
    m_alertTitle->setFont(theme::technicalFont());
    m_alertTitle->setTextFormat(Qt::PlainText);
    m_alertTitle->setWordWrap(true);

    m_alertSummary = new QLabel(m_alertBlock);
    m_alertSummary->setObjectName(QStringLiteral("alertBody"));
    m_alertSummary->setFont(theme::bodyFont());
    m_alertSummary->setTextFormat(Qt::PlainText);
    m_alertSummary->setWordWrap(true);

    m_alertMeta = new QLabel(m_alertBlock);
    m_alertMeta->setObjectName(QStringLiteral("alertMeta"));
    m_alertMeta->setFont(theme::technicalValueFont());
    m_alertMeta->setTextFormat(Qt::PlainText);
    m_alertMeta->setWordWrap(true);

    alertLayout->addWidget(m_alertTitle);
    alertLayout->addWidget(m_alertSummary);
    alertLayout->addWidget(m_alertMeta);
    bodyLayout->addWidget(m_alertBlock);

    m_separatorAboveRows = createSeparator(m_body);
    bodyLayout->addWidget(m_separatorAboveRows);

    auto* rowsLayout = new QGridLayout();
    rowsLayout->setContentsMargins(0, 0, 0, 0);
    rowsLayout->setHorizontalSpacing(theme::kSpaceMd);
    rowsLayout->setVerticalSpacing(theme::kSpaceSm);
    rowsLayout->setColumnStretch(1, 1);

    auto makeRowLabel = [this](const QString& objectName)
    {
        auto* label = new QLabel(m_body);
        label->setObjectName(objectName);
        label->setFont(theme::technicalFont());
        label->setTextFormat(Qt::PlainText);
        label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        return label;
    };
    auto makeRowValue = [this](const QString& objectName)
    {
        auto* value = new ElidedLabel(m_body);
        value->setObjectName(objectName);
        value->setFont(theme::technicalValueFont());
        value->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        return value;
    };

    m_ebpfLabel = makeRowLabel(QStringLiteral("rowLabel"));
    m_ebpfValue = makeRowValue(QStringLiteral("rowValue"));
    m_blockedLabel = makeRowLabel(QStringLiteral("rowLabel"));
    m_blockedValue = makeRowValue(QStringLiteral("rowValue"));
    m_anomalyLabel = makeRowLabel(QStringLiteral("rowLabel"));
    m_anomalyValue = makeRowValue(QStringLiteral("rowValue"));

    rowsLayout->addWidget(m_ebpfLabel, 0, 0);
    rowsLayout->addWidget(m_ebpfValue, 0, 1);
    rowsLayout->addWidget(m_blockedLabel, 1, 0);
    rowsLayout->addWidget(m_blockedValue, 1, 1);
    bodyLayout->addLayout(rowsLayout);

    // The last anomaly is an event with a long value (timestamp plus summary),
    // so it gets the full panel width instead of the narrow value column of the
    // metric grid above.
    auto* anomalyLayout = new QVBoxLayout();
    anomalyLayout->setContentsMargins(0, 0, 0, 0);
    anomalyLayout->setSpacing(2);
    anomalyLayout->addWidget(m_anomalyLabel);
    anomalyLayout->addWidget(m_anomalyValue);
    bodyLayout->addLayout(anomalyLayout);

    m_footNote = new QLabel(m_body);
    m_footNote->setObjectName(QStringLiteral("footNote"));
    m_footNote->setFont(theme::bodyFont());
    m_footNote->setTextFormat(Qt::PlainText);
    m_footNote->setWordWrap(true);
    bodyLayout->addWidget(m_footNote);

    m_consoleFailure = new QLabel(m_body);
    m_consoleFailure->setObjectName(QStringLiteral("consoleFailedNote"));
    m_consoleFailure->setFont(theme::bodyFont());
    m_consoleFailure->setTextFormat(Qt::PlainText);
    m_consoleFailure->setWordWrap(true);
    m_consoleFailure->setVisible(false);
    bodyLayout->addWidget(m_consoleFailure);

    bodyLayout->addStretch(1);
    panelLayout->addWidget(m_bodyScroll, 1);

    // --- footer: freshness, actions ----------------------------------------
    m_separatorAboveFooter = createSeparator(m_panel);
    panelLayout->addWidget(m_separatorAboveFooter);

    auto* footer = new QWidget(m_panel);
    footer->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    auto* footerLayout = new QVBoxLayout(footer);
    footerLayout->setContentsMargins(theme::kSpaceLg, theme::kSpaceMd, theme::kSpaceLg, theme::kSpaceLg);
    footerLayout->setSpacing(theme::kSpaceSm);

    m_footMeta = new QLabel(footer);
    m_footMeta->setObjectName(QStringLiteral("footMeta"));
    m_footMeta->setFont(theme::technicalValueFont());
    m_footMeta->setTextFormat(Qt::PlainText);
    m_footMeta->setWordWrap(true);

    m_buttonLayout = new QGridLayout();
    m_buttonLayout->setContentsMargins(0, 0, 0, 0);
    m_buttonLayout->setHorizontalSpacing(theme::kSpaceSm);
    m_buttonLayout->setVerticalSpacing(theme::kSpaceSm);

    m_consoleButton = new QPushButton(footer);
    m_consoleButton->setProperty("role", QStringLiteral("primary"));
    m_consoleButton->setCursor(Qt::PointingHandCursor);
    m_consoleButton->setMinimumHeight(kButtonMinimumHeight);

    m_refreshButton = new QPushButton(footer);
    m_refreshButton->setProperty("role", QStringLiteral("secondary"));
    m_refreshButton->setCursor(Qt::PointingHandCursor);
    m_refreshButton->setMinimumHeight(kButtonMinimumHeight);

    m_buttonLayout->addWidget(m_consoleButton, 0, 0);
    m_buttonLayout->addWidget(m_refreshButton, 0, 1);
    m_buttonLayout->setColumnStretch(0, 1);
    m_buttonLayout->setColumnStretch(1, 1);

    footerLayout->addWidget(m_footMeta);
    footerLayout->addLayout(m_buttonLayout);
    panelLayout->addWidget(footer);

    connect(m_consoleButton, &QPushButton::clicked, this, [this]() { launchConsole(); });
    connect(m_refreshButton,
            &QPushButton::clicked,
            this,
            [this]()
            {
                if (m_refreshPending)
                {
                    return;
                }
                setRefreshPending(true);
                emit refreshRequested();
            });

    setTabOrder(m_bodyScroll, m_consoleButton);
    setTabOrder(m_consoleButton, m_refreshButton);
}

void StatusPopup::applyStyle()
{
    setStyleSheet(theme::styleSheet());
}

void StatusPopup::retranslate()
{
    setWindowTitle(tr("GeDefense Statusanzeige"));
    setAccessibleName(tr("GeDefense Statusanzeige"));
    setAccessibleDescription(tr("Fenster mit dem aktuellen Schutzstatus dieses Rechners."));

    m_title->setText(QStringLiteral("GeDefense"));

    m_ebpfLabel->setText(tr("eBPF-Engine"));
    m_blockedLabel->setText(tr("Blockierte Angriffe heute"));
    m_anomalyLabel->setText(tr("Letzte Anomalie"));

    m_consoleButton->setText(tr("Vollständige Konsole öffnen"));
    m_consoleButton->setAccessibleName(tr("Vollständige Konsole öffnen"));
    m_consoleButton->setAccessibleDescription(tr("Startet das GeDefense-Kontrollzentrum."));
    m_refreshButton->setAccessibleName(tr("Status aktualisieren"));

    updateRefreshButton();
    refreshConsoleAvailability();
    updateFromState();
}

void StatusPopup::updateRefreshButton()
{
    if (m_refreshPending)
    {
        m_refreshButton->setText(tr("Status wird aktualisiert …"));
        m_refreshButton->setAccessibleDescription(tr("Eine Statusabfrage läuft."));
    }
    else
    {
        m_refreshButton->setText(tr("Status aktualisieren"));
        m_refreshButton->setAccessibleDescription(tr("Fragt den Status sofort erneut ab."));
    }
    m_refreshButton->setEnabled(!m_refreshPending);
}

void StatusPopup::refreshConsoleAvailability()
{
    const bool available = QFileInfo::exists(m_consoleBinaryPath);
    m_consoleButton->setEnabled(available);
    if (available)
    {
        m_consoleButton->setToolTip(tr("Öffnet die vollständige GeDefense-Konsole."));
    }
    else
    {
        m_consoleButton->setToolTip(tr("Die Konsole ist auf diesem System nicht installiert."));
    }
}

QString StatusPopup::softBreakLongWords(const QString& text, int maximumRunLength)
{
    if (maximumRunLength <= 0)
    {
        return text;
    }
    QString result;
    result.reserve(text.size() + text.size() / maximumRunLength + 1);
    int run = 0;
    for (const QChar character : text)
    {
        if (character.isSpace())
        {
            run = 0;
            result.append(character);
            continue;
        }
        result.append(character);
        ++run;
        if (run >= maximumRunLength)
        {
            result.append(QChar(kZeroWidthSpace));
            run = 0;
        }
    }
    return result;
}

QString StatusPopup::formatTimestamp(const QDateTime& value)
{
    if (!value.isValid())
    {
        return QString();
    }
    return tr("%1 UTC").arg(QLocale::system().toString(value.toUTC(), QLocale::ShortFormat));
}

// Compact stamp for table rows and the alert meta line: the value column must
// also carry the anomaly summary, so seconds and the long month name are
// omitted there. The full stamp stays in the freshness line.
QString StatusPopup::formatCompactTimestamp(const QDateTime& value)
{
    if (!value.isValid())
    {
        return QString();
    }
    return tr("%1 UTC").arg(QLocale::system().toString(value.toUTC(), QStringLiteral("dd.MM.yyyy HH:mm")));
}

QString StatusPopup::formatCounter(const std::optional<qint64>& value)
{
    if (!value.has_value())
    {
        return QString();
    }
    return QLocale::system().toString(*value);
}

void StatusPopup::updateFromState()
{
    // --- state badge and silhouette -----------------------------------------
    const QString stateKey = statusStateKey(m_state);
    m_badge->setText(labels::stateBadge(m_state));
    m_badge->setProperty("stateKind", stateKey);
    repolish(m_badge);

    const qreal ratio = devicePixelRatioF() > 0.0 ? devicePixelRatioF() : 1.0;
    m_stateIcon->setPixmap(icons::pixmap(m_state, theme::kIconSizePx, ratio));
    m_stateIcon->setAccessibleName(
        tr("Statusanzeige: %1, %2").arg(labels::stateName(m_state), labels::stateShape(m_state)));

    // --- header meta ---------------------------------------------------------
    // Visibly compact (mono technical line), explicitly described for screen
    // readers through the accessible name.
    QStringList metaParts;
    QStringList accessibleParts;
    if (!m_payload.productVersion.isEmpty())
    {
        metaParts.append(QStringLiteral("v%1").arg(m_payload.productVersion));
        accessibleParts.append(tr("Version %1").arg(m_payload.productVersion));
    }
    if (!m_payload.nodeName.isEmpty())
    {
        metaParts.append(m_payload.nodeName);
        accessibleParts.append(tr("Knoten %1").arg(m_payload.nodeName));
    }
    m_headerMeta->setFullText(metaParts.isEmpty() ? tr("Keine Angaben") : metaParts.join(QStringLiteral(" · ")));
    m_headerMeta->setAccessibleName(accessibleParts.isEmpty() ? tr("Keine Angaben")
                                                             : accessibleParts.join(QStringLiteral(" · ")));

    // --- reason line ---------------------------------------------------------
    QString reason;
    if (m_state == StatusState::Stopped)
    {
        reason = m_unavailableReason.isEmpty() ? tr("Der GeDefense-Dienst antwortet nicht.") : m_unavailableReason;
    }
    else if (!m_payload.statusReason.isEmpty())
    {
        reason = m_payload.statusReason;
    }
    else
    {
        reason = labels::stateHint(m_state);
    }
    m_reason->setText(softBreakLongWords(reason, kSoftBreakRunLength));

    // --- active alert --------------------------------------------------------
    const ActiveAlert& alert = m_payload.activeAlert;
    // A stale alert would claim an active threat that may already be resolved.
    const bool alertVisible
        = alert.present && !(m_state == StatusState::Stopped && m_payload.stale);
    m_alertBlock->setVisible(alertVisible);
    if (alertVisible)
    {
        const QString title = alert.severity.isEmpty()
            ? tr("Aktive Bedrohung")
            : tr("Aktive Bedrohung · %1").arg(alert.severity.toUpper());
        m_alertTitle->setText(softBreakLongWords(title, kSoftBreakRunLength));
        m_alertSummary->setText(softBreakLongWords(alert.summary, kSoftBreakRunLength));
        m_alertSummary->setVisible(!alert.summary.isEmpty());

        QStringList alertParts;
        const QString since = formatCompactTimestamp(alert.since);
        if (!since.isEmpty())
        {
            alertParts.append(tr("seit %1").arg(since));
        }
        if (!alert.target.isEmpty())
        {
            alertParts.append(tr("Ziel %1").arg(alert.target));
        }
        m_alertMeta->setText(softBreakLongWords(alertParts.join(QStringLiteral(" · ")), kSoftBreakRunLength));
        m_alertMeta->setVisible(!alertParts.isEmpty());
    }
    else
    {
        m_alertTitle->clear();
        m_alertSummary->clear();
        m_alertMeta->clear();
    }

    // --- rows ----------------------------------------------------------------
    const bool valuesUsable
        = m_receivedPayload && !(m_state == StatusState::Stopped && m_payload.stale);
    if (!valuesUsable)
    {
        m_ebpfValue->setFullText(tr("nicht verfügbar"));
        m_blockedValue->setFullText(tr("keine Angabe"));
        m_anomalyValue->setFullText(tr("keine Angabe"));
    }
    else
    {
        QString ebpfText;
        if (!m_payload.ebpfActive.has_value())
        {
            ebpfText = tr("nicht verfügbar");
        }
        else if (*m_payload.ebpfActive)
        {
            ebpfText = m_payload.sensor.isEmpty()
                ? tr("aktiv")
                : tr("aktiv · %1").arg(m_payload.sensor);
        }
        else
        {
            ebpfText = tr("inaktiv");
        }
        m_ebpfValue->setFullText(ebpfText);

        const QString blocked = formatCounter(m_payload.blockedActive);
        m_blockedValue->setFullText(blocked.isEmpty() ? tr("keine Angabe") : blocked);

        QString anomaly;
        const QString anomalyStamp = formatCompactTimestamp(m_payload.lastAnomalyAt);
        if (!anomalyStamp.isEmpty() && !m_payload.lastAnomalySummary.isEmpty())
        {
            anomaly = QStringLiteral("%1 · %2").arg(anomalyStamp, m_payload.lastAnomalySummary);
        }
        else if (!anomalyStamp.isEmpty())
        {
            anomaly = anomalyStamp;
        }
        else if (!m_payload.lastAnomalySummary.isEmpty())
        {
            anomaly = m_payload.lastAnomalySummary;
        }
        m_anomalyValue->setFullText(anomaly.isEmpty() ? tr("keine") : anomaly);
    }
    m_blockedValue->setAccessibleName(tr("Blockierte Angriffe heute"));
    m_ebpfValue->setAccessibleName(tr("eBPF-Engine"));
    m_anomalyValue->setAccessibleName(tr("Letzte Anomalie"));

    // --- note and freshness --------------------------------------------------
    QString note;
    if (m_state == StatusState::Stopped)
    {
        if (!m_receivedPayload)
        {
            note = tr("Es liegen keine Messwerte von diesem Rechner vor. Die Anzeige aktualisiert sich, "
                      "sobald der Dienst antwortet.");
        }
        else if (m_payload.stale)
        {
            note = tr("Die zuletzt empfangenen Werte sind veraltet und werden nicht mehr angezeigt.");
        }
        else
        {
            note = tr("Angezeigt werden die zuletzt empfangenen Werte.");
        }
    }
    else
    {
        note = labels::stateHint(m_state);
        if (m_payload.stale)
        {
            note += QStringLiteral(" ") + tr("Die Daten sind veraltet.");
        }
    }
    m_footNote->setText(softBreakLongWords(note, kSoftBreakRunLength));

    QStringList metaLines;
    if (m_receivedPayload && m_payload.generatedAt.isValid())
    {
        metaLines.append(tr("Stand: %1").arg(formatTimestamp(m_payload.generatedAt)));
    }
    else
    {
        metaLines.append(tr("Keine Messwerte empfangen"));
    }
    if (valuesUsable && m_payload.threatCountToday.has_value())
    {
        metaLines.append(tr("Bedrohungen heute: %1").arg(formatCounter(m_payload.threatCountToday)));
    }
    if (m_payload.stale && m_dataAgeMs >= 0)
    {
        metaLines.append(tr("Daten veraltet – letzte Antwort vor %1 s").arg(m_dataAgeMs / 1000));
    }
    m_footMeta->setText(metaLines.join(QStringLiteral(" · ")));
}

void StatusPopup::applyPayload(const StatusPayload& payload)
{
    m_payload = payload;
    m_receivedPayload = true;
    m_state = payload.state;
    m_unavailableReason.clear();
    updateFromState();
}

void StatusPopup::applyUnavailable(const QString& reason)
{
    m_unavailableReason = reason.isEmpty() ? tr("Der GeDefense-Dienst antwortet nicht.") : reason;
    m_state = StatusState::Stopped;
    updateFromState();
}

void StatusPopup::setRefreshPending(bool pending)
{
    m_refreshPending = pending;
    if (pending)
    {
        m_refreshSafetyTimer->start(kRefreshWatchdogMs);
    }
    else
    {
        m_refreshSafetyTimer->stop();
    }
    updateRefreshButton();
}

void StatusPopup::setDataAge(qint64 millisecondsSinceLastData)
{
    m_dataAgeMs = millisecondsSinceLastData;
    updateFromState();
}

bool StatusPopup::launchConsole()
{
    clearConsoleFailure();

    if (!QFileInfo::exists(m_consoleBinaryPath))
    {
        const QString reason = tr("Die Konsole wurde unter %1 nicht gefunden.").arg(m_consoleBinaryPath);
        showConsoleFailure(reason);
        emit consoleLaunchFailed(reason);
        return false;
    }

    if (!QProcess::startDetached(m_consoleBinaryPath, QStringList()))
    {
        const QString reason = tr("Die Konsole konnte nicht gestartet werden.");
        showConsoleFailure(reason);
        emit consoleLaunchFailed(reason);
        return false;
    }
    return true;
}

QString StatusPopup::consoleBinaryPath() const
{
    return m_consoleBinaryPath;
}

void StatusPopup::showConsoleFailure(const QString& reason)
{
    m_consoleFailureVisible = true;
    m_consoleFailure->setText(softBreakLongWords(reason, kSoftBreakRunLength));
    m_consoleFailure->setVisible(true);
}

void StatusPopup::clearConsoleFailure()
{
    if (!m_consoleFailureVisible)
    {
        return;
    }
    m_consoleFailureVisible = false;
    m_consoleFailure->clear();
    m_consoleFailure->setVisible(false);
}

void StatusPopup::setButtonsStacked(bool stacked)
{
    if (m_buttonsStacked == stacked)
    {
        return;
    }
    m_buttonsStacked = stacked;
    m_buttonLayout->removeWidget(m_consoleButton);
    m_buttonLayout->removeWidget(m_refreshButton);

    if (stacked)
    {
        m_buttonLayout->addWidget(m_consoleButton, 0, 0);
        m_buttonLayout->addWidget(m_refreshButton, 1, 0);
        m_buttonLayout->setColumnStretch(0, 1);
        m_buttonLayout->setColumnStretch(1, 0);
    }
    else
    {
        m_buttonLayout->addWidget(m_consoleButton, 0, 0);
        m_buttonLayout->addWidget(m_refreshButton, 0, 1);
        m_buttonLayout->setColumnStretch(0, 1);
        m_buttonLayout->setColumnStretch(1, 1);
    }
}

void StatusPopup::applyBodyHeightLimit(const QRect& availableGeometry)
{
    const int maximumPanelHeight = std::max(120, availableGeometry.height() - 2 * theme::kScreenMarginPx);
    setMaximumHeight(maximumPanelHeight);

    const int chromeHeight = height() - m_bodyScroll->height();
    const int allowedBody = maximumPanelHeight - chromeHeight;
    m_bodyScroll->setMaximumHeight(
        std::max(theme::kBodyMinimumHeightPx, allowedBody));
}

void StatusPopup::presentAbove(const QRect& trayGeometry, const QRect& availableGeometry)
{
    QRect available = availableGeometry;
    if (available.isEmpty())
    {
        QScreen* screen = nullptr;
        if (trayGeometry.isValid() && !trayGeometry.isEmpty())
        {
            screen = QGuiApplication::screenAt(trayGeometry.center());
        }
        if (screen == nullptr)
        {
            screen = QGuiApplication::primaryScreen();
        }
        available = screen != nullptr ? screen->availableGeometry() : QRect(0, 0, 1024, 768);
    }

    const int margin = theme::kScreenMarginPx;
    const int availableWidth = std::max(theme::kPanelWidthMinimum, available.width() - 2 * margin);

    // The button row reflows instead of being clipped when a translation is
    // long (or the screen is narrow).
    const QFontMetrics consoleMetrics(m_consoleButton->font());
    const QFontMetrics refreshMetrics(m_refreshButton->font());
    const int perButtonPadding = 2 * kButtonHorizontalPadding + 2 * kButtonBorderWidth;
    const int sideBySideWidth = consoleMetrics.horizontalAdvance(m_consoleButton->text())
        + refreshMetrics.horizontalAdvance(m_refreshButton->text()) + 2 * perButtonPadding + theme::kSpaceSm
        + 2 * theme::kSpaceLg;
    const bool stacked = sideBySideWidth > availableWidth;
    setButtonsStacked(stacked);

    const int stackedWidth = std::max(consoleMetrics.horizontalAdvance(m_consoleButton->text()),
                                      refreshMetrics.horizontalAdvance(m_refreshButton->text()))
        + perButtonPadding + 2 * theme::kSpaceLg;
    const int requiredWidth = stacked ? std::max(theme::kPanelWidthPreferred, stackedWidth)
                                      : std::max(theme::kPanelWidthPreferred, sideBySideWidth);
    setFixedWidth(clampValue(requiredWidth, theme::kPanelWidthMinimum, availableWidth));

    adjustSize(); // natural height with an unconstrained body
    applyBodyHeightLimit(available);
    adjustSize();

    const int maximumPanelHeight = std::max(120, available.height() - 2 * margin);
    resize(width(), std::min(height(), maximumPanelHeight));

    const int panelWidth = width();
    const int panelHeight = height();
    const int minimumX = available.x() + margin;
    const int maximumX = available.x() + available.width() - panelWidth - margin;
    const int minimumY = available.y() + margin;
    const int maximumY = available.y() + available.height() - panelHeight - margin;

    int x = 0;
    int y = 0;
    const bool haveTrayGeometry = trayGeometry.isValid() && !trayGeometry.isEmpty();
    if (haveTrayGeometry)
    {
        x = trayGeometry.center().x() - panelWidth / 2;
        y = trayGeometry.top() - panelHeight - theme::kTrayGapPx;
        if (y < minimumY)
        {
            // Not enough room above the icon (panel at the top of the screen or
            // a very tall flyout): flip below it.
            y = trayGeometry.bottom() + theme::kTrayGapPx;
        }
    }
    else
    {
        x = maximumX;
        y = maximumY;
    }

    move(clampValue(x, minimumX, maximumX), clampValue(y, minimumY, maximumY));
    show();
    raise();
    activateWindow();
}

void StatusPopup::dismiss()
{
    hide();
}

bool StatusPopup::isPresented() const
{
    return isVisible();
}

void StatusPopup::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Escape)
    {
        dismiss();
        event->accept();
        return;
    }
    QWidget::keyPressEvent(event);
}

void StatusPopup::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (m_consoleButton->isEnabled())
    {
        m_consoleButton->setFocus(Qt::PopupFocusReason);
    }
    else
    {
        m_refreshButton->setFocus(Qt::PopupFocusReason);
    }
}

void StatusPopup::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange)
    {
        retranslate();
    }
}

} // namespace gedefense

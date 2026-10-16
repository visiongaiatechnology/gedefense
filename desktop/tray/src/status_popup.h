// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Frameless flyout anchored to the tray icon.
//
// Properties enforced here:
//  * all text that originates from the socket is rendered as plain text
//    (QLabel::PlainText, bounded, control characters stripped) - never rich text
//  * the state is carried by icon silhouette, badge text and reason line;
//    colour is only an additional channel
//  * full keyboard operability: Escape closes, Tab order is explicit, the
//    primary action receives the initial focus
//  * the panel is clamped to the available screen geometry and scrolls its
//    body instead of leaving the screen; the button row reflows when the
//    translations are long
//  * no animation at all, so a reduced-motion preference is honoured by
//    construction (a pulsing alert is deliberately not implemented)

#pragma once

#include "status_payload.h"

#include <QString>
#include <QWidget>

class QFrame;
class QGridLayout;
class QLabel;
class QPushButton;
class QScrollArea;
class QTimer;
class QVBoxLayout;

namespace gedefense {

class ElidedLabel;

class StatusPopup : public QWidget
{
    Q_OBJECT

public:
    explicit StatusPopup(QWidget* parent = nullptr);
    explicit StatusPopup(const QString& consoleBinaryPath, QWidget* parent = nullptr);
    ~StatusPopup() override;

    StatusPopup(const StatusPopup&) = delete;
    StatusPopup& operator=(const StatusPopup&) = delete;

    // Positions the panel above the tray icon and clamps it into
    // `availableGeometry`. An empty geometry means "query the screen of the
    // tray icon, or the primary screen".
    void presentAbove(const QRect& trayGeometry, const QRect& availableGeometry = QRect());
    void dismiss();
    bool isPresented() const;

    // Applies daemon data.
    void applyPayload(const StatusPayload& payload);

    // Applies the client-defined stopped state: the daemon did not answer. The
    // panel must never look healthy in this case.
    void applyUnavailable(const QString& reason);

    // Loading state of the refresh action while a request is in flight.
    void setRefreshPending(bool pending);

    // Age of the displayed data, supplied by the controller from the client.
    // A negative value means: no answer has ever been received.
    void setDataAge(qint64 millisecondsSinceLastData);

    // Launches the full console through QProcess::startDetached with a fixed
    // absolute path and no shell. Returns false when the binary is missing or
    // could not be started; the failure is additionally surfaced in the panel.
    bool launchConsole();

    QString consoleBinaryPath() const;

signals:
    void refreshRequested();
    void consoleLaunchFailed(const QString& reason);

protected:
    void keyPressEvent(QKeyEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void changeEvent(QEvent* event) override;

private:
    void buildUi();
    void applyStyle();
    void retranslate();
    void updateFromState();
    void updateRefreshButton();
    void refreshConsoleAvailability();
    void setButtonsStacked(bool stacked);
    void applyBodyHeightLimit(const QRect& availableGeometry);
    void showConsoleFailure(const QString& reason);
    void clearConsoleFailure();
    static QString softBreakLongWords(const QString& text, int maximumRunLength);
    static QString formatTimestamp(const QDateTime& value);
    static QString formatCompactTimestamp(const QDateTime& value);
    static QString formatCounter(const std::optional<qint64>& value);

    QString m_consoleBinaryPath;
    StatusPayload m_payload;
    StatusState m_state = StatusState::Unknown;
    QString m_unavailableReason;
    qint64 m_dataAgeMs = -1;
    bool m_receivedPayload = false;
    bool m_refreshPending = false;
    bool m_buttonsStacked = false;
    bool m_consoleFailureVisible = false;
    QFrame* m_panel = nullptr;
    QFrame* m_header = nullptr;
    QLabel* m_stateIcon = nullptr;
    QLabel* m_title = nullptr;
    ElidedLabel* m_headerMeta = nullptr;
    QLabel* m_badge = nullptr;
    QScrollArea* m_bodyScroll = nullptr;
    QWidget* m_body = nullptr;
    QLabel* m_reason = nullptr;
    QFrame* m_alertBlock = nullptr;
    QLabel* m_alertTitle = nullptr;
    QLabel* m_alertSummary = nullptr;
    QLabel* m_alertMeta = nullptr;
    QFrame* m_separatorAboveRows = nullptr;
    QFrame* m_separatorAboveFooter = nullptr;
    QLabel* m_ebpfLabel = nullptr;
    ElidedLabel* m_ebpfValue = nullptr;
    QLabel* m_blockedLabel = nullptr;
    ElidedLabel* m_blockedValue = nullptr;
    QLabel* m_anomalyLabel = nullptr;
    ElidedLabel* m_anomalyValue = nullptr;
    QLabel* m_footNote = nullptr;
    QLabel* m_consoleFailure = nullptr;
    QLabel* m_footMeta = nullptr;
    QGridLayout* m_buttonLayout = nullptr;
    QPushButton* m_consoleButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QTimer* m_refreshSafetyTimer = nullptr;
};

} // namespace gedefense

// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Tray presence: icon selection per state, accessible tooltip, minimal context
// menu, and the click gesture that toggles the flyout. The controller owns no
// transport and no presentation logic - it only maps client state to tray state
// and forwards user intent.

#pragma once

#include "status_payload.h"

#include <QObject>
#include <QString>

class QAction;
class QMenu;
class QSystemTrayIcon;

namespace gedefense {

class StatusClient;
class StatusPopup;

class TrayController : public QObject
{
    Q_OBJECT

public:
    // Neither the client nor the popup is owned by the controller.
    TrayController(StatusClient* client, StatusPopup* popup, QObject* parent = nullptr);
    ~TrayController() override;

    TrayController(const TrayController&) = delete;
    TrayController& operator=(const TrayController&) = delete;

    // Creates the tray icon, wires client and popup, and starts polling.
    void start();

    bool isSystemTrayAvailable() const;
    QSystemTrayIcon* trayIcon() const;
    StatusState currentState() const;

private:
    void buildTray();
    void buildMenu();
    void updatePresentation();
    void onActivated(int reason);
    void onPayload(const StatusPayload& payload);
    void onUnavailable(const QString& reason);
    void onConsoleLaunchFailed(const QString& reason);
    void togglePopup();
    void showPopup();

    StatusClient* m_client = nullptr;
    StatusPopup* m_popup = nullptr;
    QSystemTrayIcon* m_tray = nullptr;
    QMenu* m_menu = nullptr;
    QAction* m_showAction = nullptr;
    QAction* m_refreshAction = nullptr;
    QAction* m_consoleAction = nullptr;
    StatusPayload m_payload;
    StatusState m_state = StatusState::Unknown;
    QString m_lastReason;
    bool m_havePayload = false;
    bool m_linkDown = false;
};

} // namespace gedefense

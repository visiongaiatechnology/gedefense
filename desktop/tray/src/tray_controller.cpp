// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include "tray_controller.h"

#include "app_paths.h"
#include "state_icons.h"
#include "state_labels.h"
#include "status_client.h"
#include "status_popup.h"
#include "theme.h"

#include <QAction>
#include <QFileInfo>
#include <QMenu>
#include <QStringList>
#include <QSystemTrayIcon>

namespace gedefense {
namespace {

constexpr int kTrayMessageDurationMs = 5000;

} // namespace

TrayController::TrayController(StatusClient* client, StatusPopup* popup, QObject* parent)
    : QObject(parent)
    , m_client(client)
    , m_popup(popup)
{
    buildTray();
    buildMenu();
}

TrayController::~TrayController()
{
    if (m_tray != nullptr)
    {
        m_tray->setContextMenu(nullptr);
        m_tray->hide();
    }
    delete m_menu;
    m_menu = nullptr;
}

void TrayController::buildTray()
{
    m_tray = new QSystemTrayIcon(this);

    // This tray has no quit action by design: the service owns its lifecycle.
    connect(m_tray,
            &QSystemTrayIcon::activated,
            this,
            [this](QSystemTrayIcon::ActivationReason reason) { onActivated(static_cast<int>(reason)); });

    connect(m_popup, &StatusPopup::refreshRequested, this,
            [this]()
            {
                if (m_client != nullptr)
                {
                    m_client->requestImmediate();
                }
            });
    connect(m_popup, &StatusPopup::consoleLaunchFailed, this, &TrayController::onConsoleLaunchFailed);

    if (m_client != nullptr)
    {
        connect(m_client, &StatusClient::updated, this, &TrayController::onPayload);
        connect(m_client, &StatusClient::unavailable, this, &TrayController::onUnavailable);
    }
}

void TrayController::buildMenu()
{
    m_menu = new QMenu();

    m_showAction = m_menu->addAction(QString());
    connect(m_showAction, &QAction::triggered, this, &TrayController::togglePopup);

    m_refreshAction = m_menu->addAction(QString());
    connect(m_refreshAction,
            &QAction::triggered,
            this,
            [this]()
            {
                if (m_client != nullptr)
                {
                    m_client->requestImmediate();
                }
            });

    m_menu->addSeparator();

    m_consoleAction = m_menu->addAction(QString());
    connect(m_consoleAction,
            &QAction::triggered,
            this,
            [this]()
            {
                if (m_popup != nullptr)
                {
                    m_popup->launchConsole();
                }
            });

    // The flyout is presented on demand, so the menu labels follow the
    // translation as well as the current visibility.
    connect(m_menu,
            &QMenu::aboutToShow,
            this,
            [this]()
            {
                m_showAction->setText(m_popup->isPresented() ? tr("Statusfenster schließen")
                                                             : tr("Statusfenster anzeigen"));
                m_refreshAction->setText(tr("Status aktualisieren"));
                m_consoleAction->setText(tr("Vollständige Konsole öffnen"));
                m_consoleAction->setEnabled(QFileInfo::exists(QString::fromLatin1(paths::kConsoleBinaryPath)));
            });

    m_tray->setContextMenu(m_menu);
}

void TrayController::start()
{
    updatePresentation();
    m_tray->show();
    if (m_client != nullptr)
    {
        m_client->start();
    }
}

bool TrayController::isSystemTrayAvailable() const
{
    return QSystemTrayIcon::isSystemTrayAvailable();
}

QSystemTrayIcon* TrayController::trayIcon() const
{
    return m_tray;
}

StatusState TrayController::currentState() const
{
    return m_state;
}

void TrayController::onActivated(int reason)
{
    const auto activationReason = static_cast<QSystemTrayIcon::ActivationReason>(reason);
    switch (activationReason)
    {
    case QSystemTrayIcon::Trigger:
        togglePopup();
        break;
    case QSystemTrayIcon::MiddleClick:
        if (m_client != nullptr)
        {
            m_client->requestImmediate();
        }
        break;
    case QSystemTrayIcon::Context:
    case QSystemTrayIcon::DoubleClick:
    case QSystemTrayIcon::Unknown:
        break;
    }
}

void TrayController::togglePopup()
{
    if (m_popup == nullptr)
    {
        return;
    }
    if (m_popup->isPresented())
    {
        m_popup->dismiss();
        return;
    }
    showPopup();
}

void TrayController::showPopup()
{
    if (m_popup == nullptr)
    {
        return;
    }
    const QRect trayGeometry = m_tray != nullptr ? m_tray->geometry() : QRect();
    m_popup->presentAbove(trayGeometry);
}

void TrayController::onPayload(const StatusPayload& payload)
{
    m_payload = payload;
    m_havePayload = true;
    m_linkDown = false;
    m_state = payload.state;
    m_lastReason.clear();
    if (m_popup != nullptr)
    {
        // A terminal outcome ends the pending state of the refresh action.
        m_popup->setRefreshPending(false);
    }
    updatePresentation();
}

void TrayController::onUnavailable(const QString& reason)
{
    // The client defines this state: nothing answered, therefore the tray must
    // not show a healthy state. This is distinct from a daemon that reports
    // `status: "stopped"` itself, which arrives as a payload.
    m_linkDown = true;
    m_state = StatusState::Stopped;
    m_lastReason = reason;
    if (m_popup != nullptr)
    {
        m_popup->setRefreshPending(false);
    }
    updatePresentation();
}

void TrayController::onConsoleLaunchFailed(const QString& reason)
{
    if (m_tray == nullptr)
    {
        return;
    }
    m_tray->showMessage(tr("Konsole nicht verfügbar"), reason, QSystemTrayIcon::Warning, kTrayMessageDurationMs);
}

void TrayController::updatePresentation()
{
    if (m_tray == nullptr)
    {
        return;
    }

    m_tray->setIcon(icons::icon(m_state, theme::kIconSizePx));

    QStringList tooltipParts;
    tooltipParts.append(tr("GeDefense: %1").arg(labels::stateName(m_state)));
    tooltipParts.append(labels::stateShape(m_state));
    if (m_linkDown && !m_lastReason.isEmpty())
    {
        tooltipParts.append(m_lastReason);
    }
    else if (m_havePayload && !m_payload.nodeName.isEmpty())
    {
        tooltipParts.append(tr("Knoten %1").arg(m_payload.nodeName));
    }
    if (m_payload.stale)
    {
        tooltipParts.append(tr("Daten veraltet"));
    }
    m_tray->setToolTip(tooltipParts.join(QStringLiteral(" · ")));

    if (m_popup != nullptr)
    {
        m_popup->setDataAge(m_client != nullptr ? m_client->millisecondsSinceLastSuccess() : -1);
        if (m_linkDown)
        {
            m_popup->applyUnavailable(m_lastReason);
        }
        else if (m_havePayload)
        {
            m_popup->applyPayload(m_payload);
        }
    }
}

} // namespace gedefense

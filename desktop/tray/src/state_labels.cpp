// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include "state_labels.h"

#include "theme.h"

#include <QCoreApplication>

namespace gedefense::labels {

// Every string is passed as a literal directly to QCoreApplication::translate,
// including the context. Neither a helper function nor a macro is used here,
// because neither survives lupdate's string extraction.

QString stateName(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return QCoreApplication::translate("StateLabels", "Sicher");
    case StatusState::Warning:
        return QCoreApplication::translate("StateLabels", "Warnung");
    case StatusState::Alert:
        return QCoreApplication::translate("StateLabels", "Alarm");
    case StatusState::Stopped:
        return QCoreApplication::translate("StateLabels", "Keine Verbindung");
    case StatusState::Unknown:
        break;
    }
    return QCoreApplication::translate("StateLabels", "Unbekannt");
}

QString stateBadge(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return QCoreApplication::translate("StateLabels", "SICHER");
    case StatusState::Warning:
        return QCoreApplication::translate("StateLabels", "WARNUNG");
    case StatusState::Alert:
        return QCoreApplication::translate("StateLabels", "ALARM");
    case StatusState::Stopped:
        return QCoreApplication::translate("StateLabels", "KEINE ANTWORT");
    case StatusState::Unknown:
        break;
    }
    return QCoreApplication::translate("StateLabels", "UNBEKANNT");
}

QString stateShape(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return QCoreApplication::translate("StateLabels", "geschlossenes Schild");
    case StatusState::Warning:
        return QCoreApplication::translate("StateLabels", "Schild mit Riss");
    case StatusState::Alert:
        return QCoreApplication::translate("StateLabels", "Schild mit Bruchstelle");
    case StatusState::Stopped:
        return QCoreApplication::translate("StateLabels", "Achteck, keine Verbindung");
    case StatusState::Unknown:
        break;
    }
    return QCoreApplication::translate("StateLabels", "unbekanntes Symbol");
}

QString stateHint(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return QCoreApplication::translate("StateLabels", "Alle Schutzschichten sind aktiv.");
    case StatusState::Warning:
        return QCoreApplication::translate("StateLabels", "Einzelne Schutzschichten sind eingeschränkt.");
    case StatusState::Alert:
        return QCoreApplication::translate("StateLabels", "Eine Bedrohung ist aktiv und wird behandelt.");
    case StatusState::Stopped:
        return QCoreApplication::translate("StateLabels", "Der GeDefense-Dienst antwortet nicht.");
    case StatusState::Unknown:
        break;
    }
    return QCoreApplication::translate("StateLabels", "Es liegt noch keine Statusmeldung vor.");
}

QString stateIconResource(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return QStringLiteral(":/gedefense-tray/icons/shield-secure.svg");
    case StatusState::Warning:
        return QStringLiteral(":/gedefense-tray/icons/shield-warning.svg");
    case StatusState::Alert:
        return QStringLiteral(":/gedefense-tray/icons/shield-alert.svg");
    case StatusState::Stopped:
        return QStringLiteral(":/gedefense-tray/icons/shield-stopped.svg");
    case StatusState::Unknown:
        break;
    }
    return QStringLiteral(":/gedefense-tray/icons/shield-stopped.svg");
}

QColor stateColor(StatusState state)
{
    switch (state)
    {
    case StatusState::Secure:
        return theme::color(theme::kStateSecure);
    case StatusState::Warning:
        return theme::color(theme::kStateWarning);
    case StatusState::Alert:
        return theme::color(theme::kStateAlert);
    case StatusState::Stopped:
        return theme::color(theme::kStateStopped);
    case StatusState::Unknown:
        break;
    }
    return theme::color(theme::kStateUnknown);
}

} // namespace gedefense::labels

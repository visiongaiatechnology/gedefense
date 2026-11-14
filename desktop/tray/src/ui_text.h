// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Central conversion point for untrusted text that enters a Qt rich-text sink.
//
// Qt tooltips (QLabel/QToolTip and QSystemTrayIcon::setToolTip) are rendered as
// rich text as soon as the string *looks* like HTML. Control-plane payload
// fields are only length and control-character sanitised (see
// status_payload.cpp), so a payload such as `<b>...</b>`, `<img src=...>` or
// `<a href=...>` would otherwise be interpreted as markup inside the tray UI -
// that is a UI spoofing vector (fake warnings, fake links, hidden images).
//
// Every string that originates outside this process (IPC fields, client error
// reasons, translated text) therefore passes through these helpers: the payload
// stays a literal text node and can never introduce elements or attributes.

#pragma once

#include <QChar>
#include <QString>

namespace gedefense::ui_text {

// Escaped variant for sinks that may interpret HTML. After escaping, tag
// characters and entities in the payload are inert; a markup-aware renderer
// shows the payload literally.
inline QString escaped(const QString& text)
{
    return text.toHtmlEscaped();
}

// Tooltip-safe form. The explicit <p> element makes Qt parse rich text on
// purpose (no content sniffing decides this) and the only reachable content is
// the escaped payload. Newlines become <br/> because Qt rich text collapses
// whitespace and would merge the lines.
inline QString plainTooltipText(const QString& text)
{
    QString escapedText = escaped(text);
    escapedText.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    escapedText.replace(QLatin1Char('\r'), QStringLiteral("\n"));
    escapedText.replace(QLatin1Char('\n'), QStringLiteral("<br/>"));
    return QStringLiteral("<p>") + escapedText + QStringLiteral("</p>");
}

// Escaped form for notification title/body. No HTML element is introduced, so
// a markup-capable notification server shows the payload literally and a
// plain-text server shows the escaped characters - fail-safe in both cases and
// never an injected UI element.
inline QString plainNotificationText(const QString& text)
{
    return escaped(text);
}

} // namespace gedefense::ui_text

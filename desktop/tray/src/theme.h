// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Design tokens for gedefense-tray.
//
// AUTHORITATIVE SOURCE: integration/astraeaos/gedefense-shell.cpp
// (the shipped AstraeaOS shell). Every value below is copied 1:1 from that
// file. No widget may introduce a colour, radius, font or spacing value that
// is not declared here.

#pragma once

#include <QColor>
#include <QFont>
#include <QString>

namespace gedefense::theme {

// ---------------------------------------------------------------------------
// Primitive colour tokens (gedefense-shell.cpp, lines 318-380)
// ---------------------------------------------------------------------------
inline constexpr auto kBackground = "#050912";
inline constexpr auto kHeaderBackground = "#070c16";
inline constexpr auto kFrameBorder = "#8f742e";
inline constexpr auto kHeaderBorder = "#5e4b21";
inline constexpr auto kAccent = "#d9b84a";
inline constexpr auto kText = "#f3f5f8";
inline constexpr auto kTextSecondary = "#aeb7c5";
inline constexpr auto kButtonBackground = "#171b23";
inline constexpr auto kButtonBorder = "#685425";
inline constexpr auto kButtonText = "#f4d46a";
inline constexpr auto kButtonHoverBorder = "#d9b84a";
inline constexpr auto kDangerBackground = "#9f2331";
inline constexpr auto kDangerBorder = "#d84a59";

// ---------------------------------------------------------------------------
// Geometry / typography tokens (gedefense-shell.cpp, lines 344-359)
// ---------------------------------------------------------------------------
inline constexpr int kPanelRadiusPx = 12;
inline constexpr int kPanelInnerRadiusPx = kPanelRadiusPx - 1;
inline constexpr int kButtonRadiusPx = 6;
inline constexpr int kTitlePixelSize = 13;
inline constexpr int kBodyPixelSize = 12;
inline constexpr int kTechnicalPixelSize = 10;
inline constexpr qreal kTechnicalLetterSpacingPx = 1.0;
inline constexpr qreal kTitleWeight = 600.0;

// ---------------------------------------------------------------------------
// Semantic state tokens. Derived from the primitive tokens above; the tray
// never communicates a state through colour alone (icon silhouette + text
// always carry the same information).
// ---------------------------------------------------------------------------
inline constexpr auto kStateSecure = kAccent;         // verified / enforcing
inline constexpr auto kStateWarning = "#e0a044";      // degraded, attention
inline constexpr auto kStateAlert = kDangerBorder;    // active threat
inline constexpr auto kStateStopped = "#7c8797";      // no answer from daemon
inline constexpr auto kStateUnknown = kTextSecondary; // never had data
inline constexpr auto kTextDisabled = "#6f7787";
inline constexpr auto kPressedBackground = "#0f131a";
inline constexpr auto kFocusRing = kAccent;

// ---------------------------------------------------------------------------
// Spacing scale
// ---------------------------------------------------------------------------
inline constexpr int kSpaceXs = 4;
inline constexpr int kSpaceSm = 8;
inline constexpr int kSpaceMd = 12;
inline constexpr int kSpaceLg = 16;
inline constexpr int kSpaceXl = 20;

// ---------------------------------------------------------------------------
// Layout tokens
// ---------------------------------------------------------------------------
inline constexpr int kPanelWidthPreferred = 400;
inline constexpr int kPanelWidthMinimum = 300;
inline constexpr int kTrayGapPx = 8;
inline constexpr int kScreenMarginPx = 8;
inline constexpr int kIconSizePx = 22;
inline constexpr int kPreviewIconSizePx = 20;
inline constexpr int kBodyMaxHeightRatioPercent = 45;
inline constexpr int kBodyMinimumHeightPx = 40;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
inline QString fromToken(const char* token)
{
    return QString::fromLatin1(token);
}

inline QColor color(const char* token)
{
    return QColor(fromToken(token));
}

// 600 13px "Noto Sans","Segoe UI",sans-serif
inline QFont titleFont()
{
    QFont font;
    font.setFamilies({QStringLiteral("Noto Sans"), QStringLiteral("Segoe UI")});
    font.setStyleHint(QFont::SansSerif);
    font.setPixelSize(kTitlePixelSize);
    font.setWeight(QFont::DemiBold);
    return font;
}

// 600 10px "JetBrains Mono","Noto Sans Mono",monospace, letter-spacing 1px
inline QFont technicalFont()
{
    QFont font;
    font.setFamilies({QStringLiteral("JetBrains Mono"), QStringLiteral("Noto Sans Mono")});
    font.setStyleHint(QFont::Monospace);
    font.setPixelSize(kTechnicalPixelSize);
    font.setWeight(QFont::DemiBold);
    font.setLetterSpacing(QFont::AbsoluteSpacing, kTechnicalLetterSpacingPx);
    return font;
}

// Same family as technicalFont() for machine values (counts, timestamps,
// sensors): 12px, normal weight and without tracking so that values stay
// readable and the column fits even with long content.
inline QFont technicalValueFont()
{
    QFont font;
    font.setFamilies({QStringLiteral("JetBrains Mono"), QStringLiteral("Noto Sans Mono")});
    font.setStyleHint(QFont::Monospace);
    font.setPixelSize(kBodyPixelSize);
    font.setWeight(QFont::Normal);
    font.setLetterSpacing(QFont::AbsoluteSpacing, 0.0);
    return font;
}

inline QFont bodyFont()
{
    QFont font;
    font.setFamilies({QStringLiteral("Noto Sans"), QStringLiteral("Segoe UI")});
    font.setStyleHint(QFont::SansSerif);
    font.setPixelSize(kTitlePixelSize);
    font.setWeight(QFont::Normal);
    return font;
}

inline QString stateTokenHex(const QString& stateKey)
{
    if (stateKey == QStringLiteral("secure"))
    {
        return fromToken(kStateSecure);
    }
    if (stateKey == QStringLiteral("warning"))
    {
        return fromToken(kStateWarning);
    }
    if (stateKey == QStringLiteral("alert"))
    {
        return fromToken(kStateAlert);
    }
    if (stateKey == QStringLiteral("stopped"))
    {
        return fromToken(kStateStopped);
    }
    return fromToken(kStateUnknown);
}

// Complete application style sheet. Colours, radii and borders come from the
// tokens above; fonts are applied programmatically (theme::titleFont() etc.)
// so that metrics and rendering agree.
inline QString styleSheet()
{
    const QString background = fromToken(kBackground);
    const QString headerBackground = fromToken(kHeaderBackground);
    const QString frameBorder = fromToken(kFrameBorder);
    const QString headerBorder = fromToken(kHeaderBorder);
    const QString accent = fromToken(kAccent);
    const QString text = fromToken(kText);
    const QString textSecondary = fromToken(kTextSecondary);
    const QString buttonBackground = fromToken(kButtonBackground);
    const QString buttonBorder = fromToken(kButtonBorder);
    const QString buttonText = fromToken(kButtonText);
    const QString buttonHoverBorder = fromToken(kButtonHoverBorder);
    const QString dangerBorder = fromToken(kDangerBorder);
    const QString textDisabled = fromToken(kTextDisabled);
    const QString pressedBackground = fromToken(kPressedBackground);

    const QString radius = QString::number(kPanelRadiusPx);
    const QString innerRadius = QString::number(kPanelInnerRadiusPx);
    const QString buttonRadius = QString::number(kButtonRadiusPx);

    QString css;
    css.reserve(6144);

    css += QStringLiteral("#gedefenseTrayPopup { background: transparent; }\n");
    css += QStringLiteral("#panelFrame { background: ") + background + QStringLiteral("; border: 1px solid ")
        + frameBorder + QStringLiteral("; border-radius: ") + radius + QStringLiteral("px; }\n");
    css += QStringLiteral("#headerBar { background: ") + headerBackground + QStringLiteral("; border-bottom: 1px solid ")
        + headerBorder + QStringLiteral("; border-top-left-radius: ") + innerRadius
        + QStringLiteral("px; border-top-right-radius: ") + innerRadius + QStringLiteral("px; }\n");

    css += QStringLiteral("#headerTitle { color: ") + text + QStringLiteral("; }\n");
    css += QStringLiteral("#headerMeta { color: ") + textSecondary + QStringLiteral("; }\n");

    css += QStringLiteral("#stateBadge { background: transparent; border: 1px solid ") + textSecondary
        + QStringLiteral("; border-radius: ") + buttonRadius + QStringLiteral("px; padding: 3px 8px; color: ")
        + textSecondary + QStringLiteral("; }\n");
    css += QStringLiteral("#stateBadge[stateKind=\"secure\"] { color: ") + fromToken(kStateSecure)
        + QStringLiteral("; border-color: ") + fromToken(kStateSecure) + QStringLiteral("; }\n");
    css += QStringLiteral("#stateBadge[stateKind=\"warning\"] { color: ") + fromToken(kStateWarning)
        + QStringLiteral("; border-color: ") + fromToken(kStateWarning) + QStringLiteral("; }\n");
    css += QStringLiteral("#stateBadge[stateKind=\"alert\"] { color: ") + fromToken(kStateAlert)
        + QStringLiteral("; border-color: ") + fromToken(kStateAlert) + QStringLiteral("; }\n");
    css += QStringLiteral("#stateBadge[stateKind=\"stopped\"] { color: ") + fromToken(kStateStopped)
        + QStringLiteral("; border-color: ") + fromToken(kStateStopped) + QStringLiteral("; }\n");
    css += QStringLiteral("#stateBadge[stateKind=\"unknown\"] { color: ") + textSecondary
        + QStringLiteral("; border-color: ") + textSecondary + QStringLiteral("; }\n");

    css += QStringLiteral("#reasonLabel { color: ") + text + QStringLiteral("; }\n");
    css += QStringLiteral("#rowLabel { color: ") + textSecondary + QStringLiteral("; }\n");
    css += QStringLiteral("#rowValue { color: ") + text + QStringLiteral("; }\n");
    css += QStringLiteral("#footMeta { color: ") + textSecondary + QStringLiteral("; }\n");
    css += QStringLiteral("#footNote { color: ") + textSecondary + QStringLiteral("; }\n");
    css += QStringLiteral("#sectionSeparator { background: ") + headerBorder + QStringLiteral("; border: none; }\n");

    css += QStringLiteral("#alertBlock { background: transparent; border-left: 3px solid ") + dangerBorder
        + QStringLiteral("; border-top: none; border-right: none; border-bottom: none; }\n");
    css += QStringLiteral("#alertTitle { color: ") + dangerBorder + QStringLiteral("; }\n");
    css += QStringLiteral("#alertBody { color: ") + text + QStringLiteral("; }\n");
    css += QStringLiteral("#alertMeta { color: ") + textSecondary + QStringLiteral("; }\n");

    css += QStringLiteral("#consoleFailedNote { color: ") + dangerBorder + QStringLiteral("; }\n");

    // Buttons: hover / focus / pressed / disabled are all explicit.
    css += QStringLiteral("QPushButton { background: ") + buttonBackground + QStringLiteral("; border: 1px solid ")
        + buttonBorder + QStringLiteral("; border-radius: ") + buttonRadius + QStringLiteral("px; color: ") + buttonText
        + QStringLiteral("; padding: 8px 12px; }\n");
    css += QStringLiteral("QPushButton:hover { border-color: ") + buttonHoverBorder + QStringLiteral("; }\n");
    css += QStringLiteral("QPushButton:pressed { background: ") + pressedBackground + QStringLiteral("; }\n");
    css += QStringLiteral("QPushButton:disabled { color: ") + textDisabled + QStringLiteral("; border-color: ")
        + headerBorder + QStringLiteral("; }\n");
    css += QStringLiteral("QPushButton[role=\"secondary\"] { color: ") + textSecondary + QStringLiteral("; }\n");
    css += QStringLiteral("QPushButton[role=\"secondary\"]:disabled { color: ") + textDisabled
        + QStringLiteral("; border-color: ") + headerBorder + QStringLiteral("; }\n");
    // Visible focus ring, last so that it wins over :hover. Border width is
    // compensated in padding to avoid any layout shift on focus.
    css += QStringLiteral("QPushButton:focus { border: 2px solid ") + fromToken(kFocusRing)
        + QStringLiteral("; padding: 7px 11px; }\n");

    css += QStringLiteral("QScrollArea#bodyScroll { background: transparent; border: none; }\n");
    css += QStringLiteral("#bodyViewport { background: transparent; }\n");
    css += QStringLiteral("QScrollBar:vertical { background: transparent; width: 8px; margin: 0px; }\n");
    css += QStringLiteral("QScrollBar::handle:vertical { background: ") + buttonBorder
        + QStringLiteral("; border-radius: 4px; min-height: 20px; }\n");
    css += QStringLiteral("QScrollBar::handle:vertical:hover { background: ") + accent + QStringLiteral("; }\n");
    css += QStringLiteral("QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }\n");
    css += QStringLiteral("QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }\n");

    css += QStringLiteral("QMenu { background: ") + headerBackground + QStringLiteral("; border: 1px solid ")
        + frameBorder + QStringLiteral("; border-radius: ") + buttonRadius + QStringLiteral("px; padding: 4px; }\n");
    css += QStringLiteral("QMenu::item { color: ") + text + QStringLiteral("; padding: 6px 18px; border-radius: 4px; }\n");
    css += QStringLiteral("QMenu::item:selected { background: ") + buttonBackground + QStringLiteral("; color: ")
        + buttonText + QStringLiteral("; }\n");
    css += QStringLiteral("QMenu::item:disabled { color: ") + textDisabled + QStringLiteral("; }\n");
    css += QStringLiteral("QMenu::separator { height: 1px; background: ") + headerBorder
        + QStringLiteral("; margin: 4px 8px; }\n");

    css += QStringLiteral("QToolTip { background: ") + headerBackground + QStringLiteral("; color: ") + text
        + QStringLiteral("; border: 1px solid ") + frameBorder + QStringLiteral("; padding: 4px; }\n");

    // kDangerBackground (#9f2331) is part of the mandated palette as the danger
    // *surface* colour. The tray owns no destructive action (opening the console
    // is not destructive), so nothing paints it yet; it stays declared so that a
    // future destructive surface cannot invent a colour.

    return css;
}

} // namespace gedefense::theme

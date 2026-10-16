// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Presentation mapping for StatusState. Centralised so that tray icon, badge,
// accessible description and action hint can never drift apart, and so that a
// state is always carried by three independent channels: icon silhouette,
// text, and colour.

#pragma once

#include "status_payload.h"

#include <QColor>
#include <QString>

namespace gedefense::labels {

// Human readable state name (translated).
QString stateName(StatusState state);

// Short, upper case badge text for the mono/technical font.
QString stateBadge(StatusState state);

// Description of the icon silhouette. Used in accessible descriptions and
// tooltips so that the shape itself is conveyed in text.
QString stateShape(StatusState state);

// One sentence describing what the state means and what to do about it.
QString stateHint(StatusState state);

// Qt resource path of the bundled SVG for this state.
QString stateIconResource(StatusState state);

// Semantic colour of the state, taken from the design tokens.
QColor stateColor(StatusState state);

} // namespace gedefense::labels

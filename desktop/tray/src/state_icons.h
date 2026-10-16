// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Renders the bundled SVG silhouettes at tray size. The SVGs are compiled into
// the binary through resources/gedefense-tray.qrc; no icon font, no external
// file and no network access is involved.

#pragma once

#include "status_payload.h"

#include <QIcon>
#include <QPixmap>

namespace gedefense::icons {

// Renders (and caches) the icon of a state. `devicePixelRatio` is honoured so
// that the silhouette stays crisp on HiDPI panels.
QPixmap pixmap(StatusState state, int pixelSize, qreal devicePixelRatio);

// QIcon wrapper for QSystemTrayIcon, including the disabled/unknown variant.
QIcon icon(StatusState state, int pixelSize);

} // namespace gedefense::icons

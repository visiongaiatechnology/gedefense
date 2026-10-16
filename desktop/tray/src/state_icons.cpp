// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include "state_icons.h"

#include "state_labels.h"
#include "theme.h"

#include <QHash>
#include <QPainter>
#include <QPixmap>
#include <QSvgRenderer>

#include <cmath>

namespace gedefense::icons {
namespace {

QPixmap renderFromResource(const QString& resourcePath, int pixelSize, qreal devicePixelRatio)
{
    QSvgRenderer renderer(resourcePath);
    if (!renderer.isValid())
    {
        return QPixmap();
    }

    const int deviceSize = static_cast<int>(std::lround(static_cast<double>(pixelSize) * devicePixelRatio));
    QPixmap pixmap(deviceSize, deviceSize);
    pixmap.setDevicePixelRatio(devicePixelRatio);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
    renderer.render(&painter);
    return pixmap;
}

// Defensive fallback used only when the compiled-in SVG cannot be rendered, so
// that the tray never ends up without a visible state indicator.
QPixmap renderFallback(StatusState state, int pixelSize, qreal devicePixelRatio)
{
    const int deviceSize = static_cast<int>(std::lround(static_cast<double>(pixelSize) * devicePixelRatio));
    QPixmap pixmap(deviceSize, deviceSize);
    pixmap.setDevicePixelRatio(devicePixelRatio);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    const QColor stateColor = labels::stateColor(state);
    const qreal inset = static_cast<qreal>(deviceSize) * 0.12;
    const QRectF outer(inset, inset, static_cast<qreal>(deviceSize) - 2.0 * inset,
                       static_cast<qreal>(deviceSize) - 2.0 * inset);
    painter.setPen(QPen(stateColor, std::max(1.0, static_cast<qreal>(deviceSize) * 0.08)));
    painter.setBrush(QBrush(theme::color(theme::kBackground)));
    painter.drawRoundedRect(outer, static_cast<qreal>(deviceSize) * 0.18, static_cast<qreal>(deviceSize) * 0.18);
    painter.setPen(Qt::NoPen);
    painter.setBrush(QBrush(stateColor));
    const qreal barHeight = std::max(1.0, static_cast<qreal>(deviceSize) * 0.14);
    painter.drawRect(QRectF(outer.left() + outer.width() * 0.22, outer.center().y() - barHeight / 2.0,
                            outer.width() * 0.56, barHeight));
    return pixmap;
}

QString cacheKey(StatusState state, int pixelSize, qreal devicePixelRatio)
{
    return QStringLiteral("%1|%2|%3")
        .arg(labels::stateIconResource(state))
        .arg(pixelSize)
        .arg(QString::number(devicePixelRatio, 'f', 2));
}

} // namespace

QPixmap pixmap(StatusState state, int pixelSize, qreal devicePixelRatio)
{
    const int boundedSize = std::max(1, pixelSize);
    const qreal boundedRatio = devicePixelRatio > 0.0 ? devicePixelRatio : 1.0;
    static QHash<QString, QPixmap> cache;

    const QString key = cacheKey(state, boundedSize, boundedRatio);
    const auto cached = cache.constFind(key);
    if (cached != cache.constEnd())
    {
        return cached.value();
    }

    QPixmap rendered = renderFromResource(labels::stateIconResource(state), boundedSize, boundedRatio);
    if (rendered.isNull())
    {
        rendered = renderFallback(state, boundedSize, boundedRatio);
    }
    cache.insert(key, rendered);
    return rendered;
}

QIcon icon(StatusState state, int pixelSize)
{
    QIcon result;
    result.addPixmap(pixmap(state, pixelSize, 1.0));
    result.addPixmap(pixmap(state, pixelSize, 2.0));
    return result;
}

} // namespace gedefense::icons

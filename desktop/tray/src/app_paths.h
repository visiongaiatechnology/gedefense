// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Fixed filesystem locations used by the tray client. Absolute paths only:
// no path is ever assembled from user input, and no child process is started
// through a shell.

#pragma once

#include <QByteArray>
#include <QString>

namespace gedefense::paths {

// FROZEN WIRE CONTRACT v1: read-only Unix domain socket served by the control
// plane. Never derived from user input.
inline constexpr auto kProductionSocketPath = "/run/gedefense/gedefense.sock";

// Optional override, required for tests and for non-standard deployments.
inline constexpr auto kSocketPathEnvironmentVariable = "GEDEFENSE_TRAY_SOCKET";

// Absolute path of the full console. Launched with QProcess::startDetached and
// an argument list - never through a shell, never with a relative path.
inline constexpr auto kConsoleBinaryPath = "/usr/bin/gedefense-app";

// sun_path on Linux is 108 bytes including the terminating NUL.
inline constexpr int kMaximumSocketPathBytes = 107;

// Validates a candidate socket path. Only absolute paths of bounded length are
// accepted; everything else is rejected so that the caller can fall back to the
// production path instead of silently probing attacker-controlled locations.
inline bool isAcceptableSocketPath(const QString& candidate)
{
    if (candidate.isEmpty())
    {
        return false;
    }
    if (!candidate.startsWith(QLatin1Char('/')))
    {
        return false;
    }
    if (candidate.contains(QLatin1Char('\0')))
    {
        return false;
    }
    return candidate.toUtf8().size() <= kMaximumSocketPathBytes;
}

// Resolves the socket path: GEDEFENSE_TRAY_SOCKET when it holds an acceptable
// value, the frozen production path otherwise.
inline QString resolveSocketPath(const QByteArray& environmentValue)
{
    const QString candidate = QString::fromUtf8(environmentValue);
    if (isAcceptableSocketPath(candidate))
    {
        return candidate;
    }
    return QString::fromLatin1(kProductionSocketPath);
}

} // namespace gedefense::paths

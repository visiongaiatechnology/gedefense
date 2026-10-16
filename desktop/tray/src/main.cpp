// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only
//
// Composition root. No business logic lives here: the transport client, the
// flyout and the tray controller are created, wired and started.

#include "state_icons.h"
#include "status_client.h"
#include "status_popup.h"
#include "theme.h"
#include "tray_controller.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDebug>
#include <QLocale>
#include <QString>
#include <QStringList>
#include <QTranslator>

namespace {

constexpr auto kTranslationBaseName = "gedefense-tray";

// Locale suffixes that the shipped .ts files cover. Anything else intentionally
// renders the built-in German strings.
QStringList candidateSuffixes(const QLocale& locale)
{
    QStringList suffixes;
    const QLocale::Language language = locale.language();
    const bool supported = language == QLocale::German || language == QLocale::English
        || language == QLocale::Russian || language == QLocale::Chinese;
    if (!supported)
    {
        return suffixes;
    }
    suffixes.append(locale.name());
    suffixes.append(QLocale::languageToCode(language));
    suffixes.removeDuplicates();
    return suffixes;
}

QStringList translationDirectories()
{
    const QString applicationDirectory = QCoreApplication::applicationDirPath();
    QStringList directories;
    directories.append(applicationDirectory + QStringLiteral("/i18n"));
    directories.append(applicationDirectory + QStringLiteral("/../share/gedefense-tray/i18n"));
    directories.append(QStringLiteral("/usr/local/share/gedefense-tray/i18n"));
    directories.append(QStringLiteral("/usr/share/gedefense-tray/i18n"));
    directories.removeDuplicates();
    return directories;
}

// Returns true when a compiled catalogue was loaded. Without compiled .qm files
// (no lrelease during packaging) the built-in German strings are used - the
// client never parses .ts files at runtime.
bool installTranslation(QApplication& application, const QLocale& locale)
{
    const QStringList suffixes = candidateSuffixes(locale);
    if (suffixes.isEmpty())
    {
        return false;
    }
    const QStringList directories = translationDirectories();
    for (const QString& suffix : suffixes)
    {
        for (const QString& directory : directories)
        {
            auto* translator = new QTranslator(&application);
            const QString fileName = QStringLiteral("%1_%2").arg(QString::fromLatin1(kTranslationBaseName), suffix);
            if (translator->load(fileName, directory) && application.installTranslator(translator))
            {
                qInfo("gedefense-tray: loaded translation catalogue %s from %s.",
                      qUtf8Printable(fileName),
                      qUtf8Printable(directory));
                return true;
            }
            delete translator;
        }
    }
    return false;
}

} // namespace

int main(int argc, char* argv[])
{
    // The silhouettes live in a Qt resource that is compiled into a static
    // library; without this reference the linker would drop the resource
    // initialiser and every icon would fall back to the painted placeholder.
    Q_INIT_RESOURCE(gedefense_tray);

    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("gedefense-tray"));
    QCoreApplication::setApplicationVersion(QStringLiteral(GEDEFENSE_TRAY_VERSION));
    QCoreApplication::setOrganizationName(QStringLiteral("VisionGaia Technology"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("visiongaia.de"));
    QApplication::setApplicationDisplayName(QStringLiteral("GeDefense"));
    application.setQuitOnLastWindowClosed(false);
    application.setStyleSheet(gedefense::theme::styleSheet());
    application.setWindowIcon(gedefense::icons::icon(gedefense::StatusState::Secure, 64));

    const QLocale systemLocale = QLocale::system();
    if (!installTranslation(application, systemLocale))
    {
        qInfo("gedefense-tray: no compiled translation for locale \"%s\"; using the built-in German strings.",
              qUtf8Printable(systemLocale.name()));
    }

    gedefense::StatusClient client;
    gedefense::StatusPopup popup;
    gedefense::TrayController controller(&client, &popup);
    controller.start();

    if (!controller.isSystemTrayAvailable())
    {
        // Wayland sessions without a StatusNotifierItem host have no tray at
        // all. Rather than running invisibly, present the flyout once so the
        // user sees that the client is running.
        qWarning("gedefense-tray: no system tray available; showing the status flyout directly.");
        popup.presentAbove(QRect());
    }

    return QApplication::exec();
}

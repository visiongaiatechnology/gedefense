// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

#include <QApplication>
#include <QByteArray>
#include <QColor>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPushButton>
#include <QSslCertificate>
#include <QUrl>
#include <QVBoxLayout>
#include <QWebEngineCertificateError>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestInfo>
#include <QWebEngineUrlRequestInterceptor>
#include <QWebEngineView>
#include <QWindow>

#include <memory>

namespace
{
constexpr auto kOrigin = "https://127.0.0.1:9843";
constexpr auto kCertificatePath = "/etc/vgt/gedefense/tls/access.crt";
constexpr auto kIconPath = "/usr/share/icons/hicolor/scalable/apps/astraeaos-security.svg";

bool isAllowedOrigin(const QUrl& url)
{
    return url.scheme() == QStringLiteral("https") && url.host() == QStringLiteral("127.0.0.1")
        && url.port() == 9843;
}

bool isAllowedLocalUrl(const QUrl& url)
{
    if (isAllowedOrigin(url) || url == QUrl(QStringLiteral("about:blank")))
    {
        return true;
    }
    return url.scheme() == QStringLiteral("blob")
        && url.toString().startsWith(QStringLiteral("blob:https://127.0.0.1:9843/"));
}

bool constantTimeEqual(const QByteArray& left, const QByteArray& right)
{
    if (left.size() != right.size())
    {
        return false;
    }
    unsigned char difference = 0;
    for (qsizetype index = 0; index < left.size(); ++index)
    {
        difference |= static_cast<unsigned char>(left.at(index))
            ^ static_cast<unsigned char>(right.at(index));
    }
    return difference == 0;
}

class OriginInterceptor final : public QWebEngineUrlRequestInterceptor
{
public:
    explicit OriginInterceptor(QObject* parent)
        : QWebEngineUrlRequestInterceptor(parent)
    {
    }

    void interceptRequest(QWebEngineUrlRequestInfo& info) override
    {
        if (!isAllowedLocalUrl(info.requestUrl()))
        {
            info.block(true);
        }
    }
};

class PinnedPage final : public QWebEnginePage
{
public:
    PinnedPage(QWebEngineProfile* profile, const QByteArray& pinnedDigest, QObject* parent)
        : QWebEnginePage(profile, parent)
        , m_pinnedDigest(pinnedDigest)
    {
        connect(this,
                &QWebEnginePage::certificateError,
                this,
                [this](const QWebEngineCertificateError& error)
                {
                    auto decision = error;
                    const auto chain = error.certificateChain();
                    const bool exactLeaf = !chain.isEmpty()
                        && constantTimeEqual(
                            chain.constFirst().digest(QCryptographicHash::Sha256),
                            m_pinnedDigest);
                    const bool expectedError
                        = error.type() == QWebEngineCertificateError::CertificateAuthorityInvalid;
                    if (isAllowedOrigin(error.url()) && error.isOverridable() && expectedError
                        && exactLeaf)
                    {
                        decision.acceptCertificate();
                        return;
                    }
                    decision.rejectCertificate();
                });
    }

protected:
    bool acceptNavigationRequest(
        const QUrl& url, NavigationType type, bool isMainFrame) override
    {
        Q_UNUSED(type)
        Q_UNUSED(isMainFrame)
        return isAllowedLocalUrl(url);
    }

private:
    QByteArray m_pinnedDigest;
};

class TitleBar final : public QFrame
{
public:
    explicit TitleBar(QWidget* target)
        : QFrame(target)
        , m_target(target)
    {
        setObjectName(QStringLiteral("titleBar"));
        setFixedHeight(42);

        auto* layout = new QHBoxLayout(this);
        layout->setContentsMargins(14, 0, 8, 0);
        layout->setSpacing(10);

        auto* emblem = new QLabel(this);
        emblem->setPixmap(QIcon(QString::fromUtf8(kIconPath)).pixmap(22, 22));
        emblem->setFixedSize(24, 24);
        emblem->setAccessibleName(QStringLiteral("GeDefense"));

        auto* title = new QLabel(QStringLiteral("VGT GeDefense"), this);
        title->setObjectName(QStringLiteral("windowTitle"));

        auto* state = new QLabel(QStringLiteral("●  LOCAL · PINNED TLS"), this);
        state->setObjectName(QStringLiteral("securityState"));

        auto* minimize = windowButton(QStringLiteral("−"), QStringLiteral("Minimieren"));
        auto* maximize = windowButton(QStringLiteral("□"), QStringLiteral("Maximieren"));
        auto* close = windowButton(QStringLiteral("×"), QStringLiteral("Schließen"));
        close->setObjectName(QStringLiteral("closeButton"));

        layout->addWidget(emblem);
        layout->addWidget(title);
        layout->addSpacing(8);
        layout->addWidget(state);
        layout->addStretch();
        layout->addWidget(minimize);
        layout->addWidget(maximize);
        layout->addWidget(close);

        connect(minimize, &QPushButton::clicked, target, &QWidget::showMinimized);
        connect(maximize,
                &QPushButton::clicked,
                target,
                [target, maximize]()
                {
                    if (target->isMaximized())
                    {
                        target->showNormal();
                        maximize->setText(QStringLiteral("□"));
                        maximize->setAccessibleName(QStringLiteral("Maximieren"));
                    }
                    else
                    {
                        target->showMaximized();
                        maximize->setText(QStringLiteral("❐"));
                        maximize->setAccessibleName(QStringLiteral("Wiederherstellen"));
                    }
                });
        connect(close, &QPushButton::clicked, target, &QWidget::close);
    }

protected:
    void mousePressEvent(QMouseEvent* event) override
    {
        if (event->button() == Qt::LeftButton && m_target->windowHandle())
        {
            m_target->windowHandle()->startSystemMove();
            event->accept();
            return;
        }
        QFrame::mousePressEvent(event);
    }

    void mouseDoubleClickEvent(QMouseEvent* event) override
    {
        if (event->button() == Qt::LeftButton)
        {
            m_target->isMaximized() ? m_target->showNormal() : m_target->showMaximized();
            event->accept();
            return;
        }
        QFrame::mouseDoubleClickEvent(event);
    }

private:
    QPushButton* windowButton(const QString& text, const QString& accessibleName)
    {
        auto* button = new QPushButton(text, this);
        button->setProperty("windowControl", true);
        button->setFixedSize(34, 30);
        button->setAccessibleName(accessibleName);
        button->setFocusPolicy(Qt::StrongFocus);
        return button;
    }

    QWidget* m_target;
};

std::unique_ptr<QSslCertificate> loadPinnedCertificate()
{
    const QFileInfo info(QString::fromUtf8(kCertificatePath));
    if (!info.exists() || !info.isFile() || info.isSymLink())
    {
        return nullptr;
    }

    QFile file(info.absoluteFilePath());
    if (!file.open(QIODevice::ReadOnly))
    {
        return nullptr;
    }
    const auto certificates = QSslCertificate::fromData(file.readAll(), QSsl::Pem);
    if (certificates.size() != 1 || certificates.constFirst().isNull())
    {
        return nullptr;
    }
    return std::make_unique<QSslCertificate>(certificates.constFirst());
}

void showOpaqueFailure(const QString& message)
{
    QMessageBox box(
        QMessageBox::Critical,
        QStringLiteral("VGT GeDefense"),
        message,
        QMessageBox::Close);
    box.setDetailedText(QString());
    box.exec();
}
} // namespace

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("VGT GeDefense"));
    QApplication::setOrganizationName(QStringLiteral("VisionGaiaTechnology"));
    QApplication::setWindowIcon(QIcon(QString::fromUtf8(kIconPath)));

    const auto certificate = loadPinnedCertificate();
    if (!certificate)
    {
        showOpaqueFailure(QStringLiteral(
            "Die lokale GeDefense-Sicherheitsidentität ist nicht verfügbar."));
        return 1;
    }

    QWidget window;
    window.setObjectName(QStringLiteral("gedefenseWindow"));
    window.setWindowTitle(QStringLiteral("VGT GeDefense"));
    window.setWindowIcon(QIcon(QString::fromUtf8(kIconPath)));
    window.setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    window.setAttribute(Qt::WA_TranslucentBackground);
    window.resize(1280, 820);
    window.setMinimumSize(1024, 680);

    auto* outer = new QVBoxLayout(&window);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(0);

    auto* shell = new QFrame(&window);
    shell->setObjectName(QStringLiteral("shellFrame"));
    auto* shellLayout = new QVBoxLayout(shell);
    shellLayout->setContentsMargins(1, 1, 1, 1);
    shellLayout->setSpacing(0);

    auto* titleBar = new TitleBar(&window);
    auto* profile = new QWebEngineProfile(&window);
    profile->setHttpCacheType(QWebEngineProfile::NoCache);
    profile->setPersistentCookiesPolicy(QWebEngineProfile::NoPersistentCookies);
    profile->setSpellCheckEnabled(false);
    profile->setPushServiceEnabled(false);
    profile->settings()->setAttribute(QWebEngineSettings::JavascriptCanOpenWindows, false);
    profile->settings()->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, false);
    profile->settings()->setAttribute(QWebEngineSettings::HyperlinkAuditingEnabled, false);
    profile->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
    profile->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, false);
    profile->settings()->setAttribute(QWebEngineSettings::ScreenCaptureEnabled, false);
    profile->settings()->setAttribute(QWebEngineSettings::PluginsEnabled, false);

    auto* interceptor = new OriginInterceptor(profile);
    profile->setUrlRequestInterceptor(interceptor);

    auto* view = new QWebEngineView(shell);
    view->setObjectName(QStringLiteral("securityCenter"));
    view->setContextMenuPolicy(Qt::NoContextMenu);
    auto* page = new PinnedPage(
        profile,
        certificate->digest(QCryptographicHash::Sha256),
        view);
    page->setBackgroundColor(QColor(QStringLiteral("#050912")));
    view->setPage(page);

    QObject::connect(
        view,
        &QWebEngineView::loadFinished,
        &window,
        [&window](bool success)
        {
            if (!success)
            {
                showOpaqueFailure(QStringLiteral(
                    "Das GeDefense Security Center konnte nicht sicher geladen werden."));
                window.close();
            }
        });

    shellLayout->addWidget(titleBar);
    shellLayout->addWidget(view, 1);
    outer->addWidget(shell);

    window.setStyleSheet(QStringLiteral(R"(
        #gedefenseWindow { background: transparent; }
        #shellFrame {
            background: #050912;
            border: 1px solid #8f742e;
            border-radius: 12px;
        }
        #titleBar {
            background: #070c16;
            border-bottom: 1px solid #5e4b21;
            border-top-left-radius: 11px;
            border-top-right-radius: 11px;
        }
        #windowTitle {
            color: #f3f5f8;
            font: 600 13px "Noto Sans", "Segoe UI", sans-serif;
        }
        #securityState {
            color: #d9b84a;
            font: 600 10px "JetBrains Mono", "Noto Sans Mono", monospace;
            letter-spacing: 1px;
        }
        QPushButton[windowControl="true"] {
            color: #aeb7c5;
            background: transparent;
            border: 1px solid transparent;
            border-radius: 6px;
            font-size: 17px;
        }
        QPushButton[windowControl="true"]:hover {
            color: #f4d46a;
            background: #171b23;
            border-color: #685425;
        }
        QPushButton[windowControl="true"]:focus {
            border-color: #d9b84a;
        }
        #closeButton:hover {
            color: white;
            background: #9f2331;
            border-color: #d84a59;
        }
    )"));

    view->load(QUrl(QString::fromUtf8(kOrigin)));
    window.show();
    return application.exec();
}

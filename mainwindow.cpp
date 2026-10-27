#include "mainwindow.h"
#include "qrscanner.h"
#include "store.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QMessageBox>
#include <QStatusBar>
#include <QTimer>
#include <QToolBar>
#include <QTreeWidget>

MainWindow::MainWindow()
{
    setWindowTitle("QAuth");
    resize(560, 380);

    m_tree = new QTreeWidget;
    m_tree->setColumnCount(3);
    m_tree->setHeaderLabels({ "Account", "Code", "Expires" });
    m_tree->setRootIsDecorated(false);
    m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    QFont mono = m_tree->font();
    mono.setPointSize(mono.pointSize() + 4);
    mono.setFamily("Consolas");
    m_tree->setFont(mono);
    setCentralWidget(m_tree);
    connect(m_tree, &QTreeWidget::itemDoubleClicked, this, &MainWindow::copySelected);

    QToolBar *tb = addToolBar("Main");
    tb->setMovable(false);
    tb->addAction("Scan screen for QR", this, &MainWindow::scanScreen);
    tb->addAction("Open QR image…", this, &MainWindow::scanImageFile);
    tb->addAction("Add manually…", this, &MainWindow::addManually);
    tb->addSeparator();
    tb->addAction("Copy code", this, &MainWindow::copySelected);
    tb->addAction("Remove", this, &MainWindow::removeSelected);

    m_accounts = Store::load();
    rebuild();

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &MainWindow::tick);
    m_timer->start(250);
    statusBar()->showMessage("Double-click an entry to copy its code.");
}

void MainWindow::rebuild()
{
    m_tree->clear();
    for (const Account &a : m_accounts)
        m_tree->addTopLevelItem(new QTreeWidgetItem({ a.label(), QString(), QString() }));
    tick();
}

void MainWindow::tick()
{
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (int i = 0; i < m_accounts.size() && i < m_tree->topLevelItemCount(); ++i) {
        const Account &a = m_accounts[i];
        QString c = Totp::code(a, now);
        if (c.size() == 6) c.insert(3, ' ');
        else if (c.size() == 8) c.insert(4, ' ');
        QTreeWidgetItem *it = m_tree->topLevelItem(i);
        it->setText(1, c.isEmpty() ? "invalid" : c);
        it->setText(2, QString("%1 s").arg(Totp::secondsRemaining(a, now)));
    }
}

void MainWindow::persist()
{
    if (!Store::save(m_accounts))
        QMessageBox::warning(this, "QAuth", "Could not save your accounts to disk.");
}

bool MainWindow::addAccount(const Account &a)
{
    for (const Account &e : std::as_const(m_accounts))
        if (e.secret == a.secret && e.issuer == a.issuer && e.name == a.name) return false;
    m_accounts << a;
    return true;
}

void MainWindow::importPayloads(const QStringList &payloads)
{
    int added = 0;
    QString lastError;
    for (const QString &p : payloads) {
        QString err;
        auto acc = Totp::parseUri(p, &err);
        if (!acc) { lastError = err; continue; }
        const auto btn = QMessageBox::question(this, "Add account?",
                                               QString("Found: %1\n\nAdd it to QAuth?").arg(acc->label()));
        if (btn == QMessageBox::Yes && addAccount(*acc)) ++added;
    }
    if (added) { persist(); rebuild(); statusBar()->showMessage(QString("Added %1 account(s).").arg(added), 5000); }
    else if (payloads.isEmpty()) QMessageBox::information(this, "QAuth", "No QR code was found.");
    else if (!lastError.isEmpty()) QMessageBox::warning(this, "QAuth", lastError);
}

void MainWindow::scanScreen()
{
    // Get our own window out of the way so it can't cover the QR code.
    showMinimized();
    QTimer::singleShot(600, this, [this] {
        const QStringList found = QrScanner::scanScreens();
        showNormal();
        raise();
        activateWindow();
        importPayloads(found);
    });
}

void MainWindow::scanImageFile()
{
    const QString file = QFileDialog::getOpenFileName(this, "Open QR code image", {},
                                                      "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)");
    if (file.isEmpty()) return;
    importPayloads(QrScanner::decode(QImage(file)));
}

void MainWindow::addManually()
{
    QDialog dlg(this);
    dlg.setWindowTitle("Add account manually");
    auto *form = new QFormLayout(&dlg);
    auto *issuer = new QLineEdit, *name = new QLineEdit, *secret = new QLineEdit;
    form->addRow("Service (e.g. GitHub):", issuer);
    form->addRow("Account (e.g. you@mail.com):", name);
    form->addRow("Secret key (Base32):", secret);
    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    form->addRow(bb);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted) return;

    Account a;
    a.issuer = issuer->text().trimmed();
    a.name = name->text().trimmed();
    a.secret = secret->text().remove(' ').remove('-').toUpper();
    bool ok = false;
    Totp::base32Decode(a.secret, &ok);
    if (!ok || a.secret.isEmpty()) {
        QMessageBox::warning(this, "QAuth", "That secret key isn't valid Base32.");
        return;
    }
    if (a.issuer.isEmpty() && a.name.isEmpty()) a.name = "Account";
    if (addAccount(a)) { persist(); rebuild(); }
}

void MainWindow::removeSelected()
{
    const int row = m_tree->indexOfTopLevelItem(m_tree->currentItem());
    if (row < 0) return;
    if (QMessageBox::warning(this, "Remove account",
            QString("Remove %1?\n\nMake sure you can still log in to that service without this code.")
                .arg(m_accounts[row].label()),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) return;
    m_accounts.removeAt(row);
    persist();
    rebuild();
}

void MainWindow::copySelected()
{
    const int row = m_tree->indexOfTopLevelItem(m_tree->currentItem());
    if (row < 0) return;
    const QString code = Totp::code(m_accounts[row], QDateTime::currentSecsSinceEpoch());
    if (code.isEmpty()) return;
    QClipboard *cb = QApplication::clipboard();
    cb->setText(code);
    statusBar()->showMessage("Code copied. Clipboard clears in 20 seconds.", 5000);
    QTimer::singleShot(20000, this, [cb, code] { if (cb->text() == code) cb->clear(); });
}

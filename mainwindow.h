#pragma once
#include "totp.h"
#include <QMainWindow>
#include <QVector>

class QTreeWidget;
class QTreeWidgetItem;
class QTimer;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow();

private slots:
    void tick();
    void scanScreen();
    void scanImageFile();
    void addManually();
    void removeSelected();
    void copySelected();

private:
    void rebuild();
    void persist();
    void importPayloads(const QStringList &payloads);
    bool addAccount(const Account &a);

    QVector<Account> m_accounts;
    QTreeWidget *m_tree;
    QTimer *m_timer;
};

#pragma once
#include "totp.h"
#include <QVector>

namespace Store {
QString path();
QVector<Account> load();
bool save(const QVector<Account> &accounts);
}

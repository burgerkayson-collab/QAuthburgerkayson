#include "store.h"
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStandardPaths>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

namespace Store {

// On Windows the file is encrypted with DPAPI (tied to the current Windows user).
// On other platforms it is plain JSON with owner-only permissions.
static QByteArray protect(const QByteArray &plain)
{
#ifdef _WIN32
    DATA_BLOB in{ DWORD(plain.size()), reinterpret_cast<BYTE *>(const_cast<char *>(plain.constData())) };
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"QAuth accounts", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return {};
    QByteArray r(reinterpret_cast<char *>(out.pbData), int(out.cbData));
    LocalFree(out.pbData);
    return r;
#else
    return plain;
#endif
}

static QByteArray unprotect(const QByteArray &data)
{
#ifdef _WIN32
    DATA_BLOB in{ DWORD(data.size()), reinterpret_cast<BYTE *>(const_cast<char *>(data.constData())) };
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return {};
    QByteArray r(reinterpret_cast<char *>(out.pbData), int(out.cbData));
    LocalFree(out.pbData);
    return r;
#else
    return data;
#endif
}

QString path()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + "/accounts.dat";
}

QVector<Account> load()
{
    QVector<Account> list;
    QFile f(path());
    if (!f.open(QIODevice::ReadOnly)) return list;
    const QJsonDocument doc = QJsonDocument::fromJson(unprotect(f.readAll()));
    for (const QJsonValue &v : doc.array()) {
        const QJsonObject o = v.toObject();
        Account a;
        a.issuer = o["issuer"].toString();
        a.name = o["name"].toString();
        a.secret = o["secret"].toString();
        a.algorithm = o["algorithm"].toString("SHA1");
        a.digits = o["digits"].toInt(6);
        a.period = o["period"].toInt(30);
        if (!a.secret.isEmpty()) list << a;
    }
    return list;
}

bool save(const QVector<Account> &accounts)
{
    QJsonArray arr;
    for (const Account &a : accounts)
        arr.append(QJsonObject{ {"issuer", a.issuer}, {"name", a.name}, {"secret", a.secret},
                                {"algorithm", a.algorithm}, {"digits", a.digits}, {"period", a.period} });
    const QByteArray blob = protect(QJsonDocument(arr).toJson(QJsonDocument::Compact));
    if (blob.isEmpty()) return false;

    QSaveFile f(path());
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    f.write(blob);
    return f.commit();
}

} // namespace Store

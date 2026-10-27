#pragma once
#include <QString>
#include <QByteArray>
#include <optional>

struct Account {
    QString issuer;
    QString name;
    QString secret;              // Base32, upper-case, no spaces
    QString algorithm = "SHA1";  // SHA1 | SHA256 | SHA512
    int digits = 6;
    int period = 30;

    QString label() const {
        if (issuer.isEmpty()) return name;
        if (name.isEmpty()) return issuer;
        return issuer + " (" + name + ")";
    }
};

namespace Totp {
QByteArray base32Decode(const QString &in, bool *ok = nullptr);
QString code(const Account &a, qint64 unixSecs);           // empty string if secret is invalid
int secondsRemaining(const Account &a, qint64 unixSecs);
// Parses otpauth://totp/Issuer:name?secret=...&issuer=...&algorithm=...&digits=...&period=...
std::optional<Account> parseUri(const QString &text, QString *error = nullptr);
}

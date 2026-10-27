#include "totp.h"
#include <QMessageAuthenticationCode>
#include <QCryptographicHash>
#include <QUrl>
#include <QUrlQuery>

namespace Totp {

QByteArray base32Decode(const QString &in, bool *ok)
{
    if (ok) *ok = true;
    QByteArray out;
    quint32 buffer = 0;
    int bits = 0;
    for (QChar qc : in) {
        char c = qc.toUpper().toLatin1();
        if (c == ' ' || c == '-' || c == '=') continue;
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else { if (ok) *ok = false; return {}; }
        buffer = (buffer << 5) | quint32(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.append(char((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

static QCryptographicHash::Algorithm hashFor(const QString &name)
{
    if (name == "SHA256") return QCryptographicHash::Sha256;
    if (name == "SHA512") return QCryptographicHash::Sha512;
    return QCryptographicHash::Sha1;
}

QString code(const Account &a, qint64 unixSecs)
{
    bool ok = false;
    const QByteArray key = base32Decode(a.secret, &ok);
    if (!ok || key.isEmpty() || a.period <= 0) return {};

    quint64 counter = quint64(unixSecs / a.period);
    QByteArray msg(8, 0);
    for (int i = 7; i >= 0; --i) { msg[i] = char(counter & 0xFF); counter >>= 8; }

    const QByteArray h = QMessageAuthenticationCode::hash(msg, key, hashFor(a.algorithm));
    const int o = h.at(h.size() - 1) & 0x0F;
    const quint32 bin = (quint32(h.at(o) & 0x7F) << 24) | (quint32(h.at(o + 1) & 0xFF) << 16)
                      | (quint32(h.at(o + 2) & 0xFF) << 8) | quint32(h.at(o + 3) & 0xFF);

    const int digits = qBound(6, a.digits, 8);
    quint32 mod = 1;
    for (int i = 0; i < digits; ++i) mod *= 10;
    return QString::number(bin % mod).rightJustified(digits, '0');
}

int secondsRemaining(const Account &a, qint64 unixSecs)
{
    const int p = a.period > 0 ? a.period : 30;
    return p - int(unixSecs % p);
}

std::optional<Account> parseUri(const QString &text, QString *error)
{
    auto fail = [&](const QString &m) -> std::optional<Account> { if (error) *error = m; return std::nullopt; };

    const QUrl url(text.trimmed());
    if (url.scheme().toLower() != "otpauth")
        return fail("Not an otpauth:// code.");
    if (url.host().toLower() != "totp")
        return fail("Only time-based (TOTP) codes are supported.");

    const QUrlQuery q(url);
    Account a;
    a.secret = q.queryItemValue("secret").remove(' ').remove('=').toUpper();
    bool ok = false;
    base32Decode(a.secret, &ok);
    if (!ok || a.secret.isEmpty())
        return fail("The code contains an invalid secret.");

    QString label = url.path();
    if (label.startsWith('/')) label.remove(0, 1);
    const int colon = label.indexOf(':');
    if (colon >= 0) { a.issuer = label.left(colon).trimmed(); a.name = label.mid(colon + 1).trimmed(); }
    else a.name = label.trimmed();
    if (q.hasQueryItem("issuer")) a.issuer = q.queryItemValue("issuer").trimmed();

    const QString alg = q.queryItemValue("algorithm").toUpper();
    if (!alg.isEmpty()) {
        if (alg != "SHA1" && alg != "SHA256" && alg != "SHA512")
            return fail("Unsupported algorithm: " + alg);
        a.algorithm = alg;
    }
    if (q.hasQueryItem("digits")) {
        a.digits = q.queryItemValue("digits").toInt();
        if (a.digits < 6 || a.digits > 8) return fail("Unsupported digit count.");
    }
    if (q.hasQueryItem("period")) {
        a.period = q.queryItemValue("period").toInt();
        if (a.period <= 0) return fail("Invalid period.");
    }
    return a;
}

} // namespace Totp

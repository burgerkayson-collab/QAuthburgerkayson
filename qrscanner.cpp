#include "qrscanner.h"
#include <QGuiApplication>
#include <QPixmap>
#include <QScreen>
#include <ReadBarcode.h>

namespace QrScanner {

static void decodeOnce(const QImage &src, QStringList &out)
{
    const QImage gray = src.convertToFormat(QImage::Format_Grayscale8);
    ZXing::ImageView view(gray.constBits(), gray.width(), gray.height(),
                          ZXing::ImageFormat::Lum, int(gray.bytesPerLine()));
    ZXing::ReaderOptions opts;
    opts.setFormats(ZXing::BarcodeFormat::QRCode);
    opts.setTryHarder(true);
    opts.setTryRotate(true);
    opts.setTryInvert(true);
    for (const auto &r : ZXing::ReadBarcodes(view, opts)) {
        if (!r.isValid()) continue;
        const QString t = QString::fromStdString(r.text());
        if (!out.contains(t)) out << t;
    }
}

QStringList decode(const QImage &image)
{
    QStringList out;
    if (image.isNull()) return out;
    decodeOnce(image, out);
    // Fallback: very large / hi-DPI captures sometimes decode better when shrunk
    if (out.isEmpty() && image.width() > 1600)
        decodeOnce(image.scaledToWidth(image.width() / 2, Qt::SmoothTransformation), out);
    return out;
}

QStringList scanScreens()
{
    QStringList out;
    for (QScreen *screen : QGuiApplication::screens()) {
        for (const QString &t : decode(screen->grabWindow(0).toImage()))
            if (!out.contains(t)) out << t;
    }
    return out;
}

} // namespace QrScanner

#pragma once
#include <QImage>
#include <QStringList>

namespace QrScanner {
QStringList decode(const QImage &image);   // all QR payloads found in the image
QStringList scanScreens();                 // captures every monitor and decodes
}

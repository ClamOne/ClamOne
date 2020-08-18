#ifndef GUNCOMPRESS_H
#define GUNCOMPRESS_H

#include <QObject>
#include <QDebug>

#include <zlib.h>

QByteArray gUncompress(const QByteArray &data);

#endif // GUNCOMPRESS_H

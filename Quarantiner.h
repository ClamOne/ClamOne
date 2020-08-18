#ifndef QUARANTINER_H
#define QUARANTINER_H

#include <QObject>
#include <QFileInfo>
#include <QDir>

#include <QDebug>

#include "QAES.h"

class Quarantiner: public QObject
{
    Q_OBJECT

public slots:
    void process();

signals:
    void finished();
    void error(QString err);
    void updateDbQuarantine(QByteArray quarantine_name, quint32 timestamp, quint64 file_size, QByteArray file_name, quint8 verified);
    void remove(QByteArray crypt_filename, QByteArray plain_filename);
    void updateQuaramtineCount(quint32 timestamp);

public:
    Quarantiner(QByteArray fname, QByteArray quar_dirname, QByteArray random);

private:
    QByteArray filename;
    QByteArray quarantine_dirname;
    QByteArray randb;
};

#endif // QUARANTINER_H

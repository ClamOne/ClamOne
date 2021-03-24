#include "CkProc.h"

void ckProcs(int *pidClamd, int *pidFreshclam, int *pidClamonacc){
    bool ok;
    QDir procdir("/proc");

    (*pidClamd) = -1;
    (*pidFreshclam) = -1;
    (*pidClamonacc) = -1;

    procdir.entryList();
    procdir.setFilter(QDir::Dirs | QDir::NoSymLinks);
    procdir.setSorting(QDir::Name);

    QFileInfoList list = procdir.entryInfoList();
    for (int i = 0; i < list.size(); ++i) {
        QString freadall = QString();
        QFileInfo proccmdline, fileInfo = list.at(i);
        int num = QString(fileInfo.fileName()).toInt(&ok, 10);
        if(!ok)
            continue;
        proccmdline = QFileInfo(fileInfo.absoluteFilePath()+"/cmdline");
        if(!proccmdline.exists())
            continue;
        QFile f(proccmdline.absoluteFilePath());
        if(f.open(QFile::ReadOnly)){
            freadall = QString(f.readAll());
            f.close();
        }else
            continue;
        if(freadall.isEmpty())
            continue;
        freadall = QFileInfo(freadall).baseName();
        if(freadall == QString("clamd")){
            if(pidClamd != Q_NULLPTR)
                (*pidClamd) = num;
        }else if(freadall == QString("freshclam")){
            if(pidFreshclam != Q_NULLPTR)
                (*pidFreshclam) = num;
        }else if(freadall == QString("clamonacc")){
            if(pidClamonacc != Q_NULLPTR)
                (*pidClamonacc) = num;
        }
    }
}

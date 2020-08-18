#include "Quarantiner.h"

Quarantiner::Quarantiner(QByteArray fname, QByteArray quar_dirname, QByteArray random){
    filename = fname;
    quarantine_dirname = quar_dirname;
    randb = random;
}

void Quarantiner::process(){
    qDebug() << "begin Quarantine process";
    QByteArray qba;
    QFileInfo qfd(quarantine_dirname);
    if(!qfd.exists())
        QDir().mkpath(qfd.absoluteFilePath());
    if(!qfd.isDir() || !qfd.isWritable()){
        qDebug() << "cannot make quarantine directory";
        return;
    }
    //Quarantine
    QByteArray randFileName = randb;
    randFileName = QString(randFileName.toBase64()).replace("/", "_").toLocal8Bit();
    QFile quarantine_file_name(qfd.absolutePath()+tr("/")+randFileName);
    if(!quarantine_file_name.open(QIODevice::WriteOnly)){
        qDebug() << "new quarantine file is not writable: " << quarantine_file_name.fileName();
        return;
    }

    quint32 timestamp = time(NULL);
    QFile orig_file_name(filename);
    if(orig_file_name.open(QIODevice::ReadOnly)){
        qDebug() << "Lock quarantine file in progress";
        qba = orig_file_name.readAll();
        quarantine_file_name.write(QAES().lock(filename, qba, &timestamp));
        orig_file_name.close();
        qDebug() << "Lock file complete";
    }else{
        qDebug() << "orginal quarantine file is not readable: " << orig_file_name.fileName();
        quarantine_file_name.close();
    }
    quarantine_file_name.close();

    //Verify the stowed file
    qDebug() << "Verify the stowed file";
    QByteArray fname;
    quint32 ts;
    if(!quarantine_file_name.open(QIODevice::ReadOnly)){
        return;
    }
    if(QAES().verify(quarantine_file_name.readAll(), &fname, &ts) && fname == filename && ts == timestamp ){
        quarantine_file_name.close();
        emit updateDbQuarantine(randFileName, ts, (quint64)qba.length(), fname, 2);
        emit remove(quarantine_file_name.fileName().toLocal8Bit(), orig_file_name.fileName().toLocal8Bit());
        emit updateQuaramtineCount((quint32)time(NULL));
    }else{
        quarantine_file_name.close();
        emit updateDbQuarantine(randFileName, ts, (quint64)qba.length(), fname, 3);
    }

    qDebug() << "end Quarantine process";

}

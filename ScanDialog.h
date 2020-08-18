#ifndef SCANDIALOG_H
#define SCANDIALOG_H

#include <QDialog>
#include <QFileInfo>
#include <QFileDialog>
#include <QProcess>
#include <QScrollBar>
#include <QMovie>
#include <QMimeData>
#include <QDragEnterEvent>

#include "confs.h"

#include <QDebug>

namespace Ui {
class ScanDialog;
}

class ScanDialog : public QDialog
{
    Q_OBJECT
private slots:
    void on_pushButtonErrorClose_clicked();
    void on_pushButtonQuickClose_clicked();
    void on_pushButtonDeepClose_clicked();
    void on_pushButtonQuickScan_clicked();
    void on_pushButtonDeepScan_clicked();
    void on_pushButtonAddFiles_clicked();
    void on_pushButtonAddDir_clicked();
    void on_pushButtonRunningAbort_clicked();
    void on_pushButtonRunningClose_clicked();
    void removeQuickItemAt(const QString & link);
    void removeDeepItemAt(const QString & link);
    void addNextItem(const QString &name, ClamOneScanStackOrder type);

signals:
    void parseClamdscanLine(QByteArray line);
    void setScanActive(bool state);
    void initScanProcess(QStringList listWidgetToStringList);
    void remoteProcKill();

public:
    explicit ScanDialog(QWidget *parent = 0);
    ~ScanDialog();

    void initializeQuickScan(bool active);
    void initializeDeepScan(bool active);

public slots:
    void processReadyRead(QByteArray buffer);
    void processFinished();
    void initializeFreelanceScan(bool active, QStringList stringlist);

private:
    Ui::ScanDialog *ui;

    void colorize(QString color);
    void defaultClose();
    QStringList quickListWidgetToStringList();
    QStringList deepListWidgetToStringList();
    QString getClamdscanPath();

protected:
    void dragEnterEvent(QDragEnterEvent *e);
    void dropEvent(QDropEvent *e);
    void closeEvent(QCloseEvent *event) override;
};

#endif // SCANDIALOG_H

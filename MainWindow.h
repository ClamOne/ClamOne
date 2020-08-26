#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QTimer>
#include <QProcess>
#include <QFileSystemWatcher>
#include <QStandardPaths>
#include <QMessageBox>
#include <QLineEdit>
#include <QDoubleSpinBox>
#include <QMenu>
#include <QLocalSocket>
#include <QFileInfo>
#include <QThread>
#include <QQueue>
#include <QDateTime>
#include <QBuffer>
#include <QBarSeries>
#include <QBarSet>
#include <QBarCategoryAxis>

#include <QDateTimeAxis>
#include <QValueAxis>

#include <QSqlDatabase>
#include <QSqlDriver>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>

#include <QDnsLookup>

#include <experimental/filesystem>

//loading dynamically
#include <dlfcn.h>

//from libprocps4-dev
#include <proc/readproc.h>

//#include <unistd.h>
//#include <sys/types.h>
//getpwnam user to pid/gid
#include <pwd.h>

#include <cmath>

#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>

#include <QDebug>

#include "AboutDialog.h"
#include "ConfigureDialogCurrent.h"
#include "ScanDialog.h"
#include "ListerQuarantine.h"
#include "Quarantiner.h"
#include "ScheduleItem.h"
#include "TimestampTableWidgetItem.h"

#include "qstringlistwidget.h"

#include "confs.h"
#include "gUncompress.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

    struct ClamavDNSDataStruct {
        quint16 ver_major;
        quint16 ver_minor;
        quint16 ver_build;
        quint32 ver_compiled;
        quint16 main_ver;
        quint16 daily_ver;
        quint16 bytecode_ver;
        quint32 timestamp;
        quint32 last_lookup_timestamp;
        quint16 flevel;
        bool isReset;
    };

    struct ClamavDefHeader {
        QString db_name;
        QString timestamp_str;
        quint32 version;
        quint32 num_unknown;
        quint16 flevel;
        QString user_name;
        quint32 timestamp;
    };

private slots:
    void iconActivated(QSystemTrayIcon::ActivationReason reason);
    void allHide();
    void allShow();
    void statusShow();
    void scanShow();
    void updateShow();
    void historyShow();
    void aboutLaunch();
    void configLaunch();
    bool find_file(QByteArray *filepath, QString name);
    quint32 checkCurrentClamavVersionInstalled();
    bool setupDb();
    void markClamOneStarted();
    void markClamOneStopped();
    void loadScheduleFromDb();
    void markQuarantineNewFile(QByteArray filename);
    void markQuarantineDeleteQ(QByteArray filename);
    void markQuarantineUnQ(QByteArray filename);
    void stackedWidgetChanged(int index);
    bool addExistingEvents();
    bool addExistingEventsParseClamlog(QString filename, bool verify, bool active);
    bool addExistingEventsParseFreshclam(QString filename, bool verify);
    bool parseClamavLogLine(QByteArray line, qint64 *ts, QString *msg, bool *found);
    void parseClamdscanLine(QByteArray line);
    void insertIntoFoundOrGeneral(qint64 timestamp, QString message, bool found, bool active);
    bool parseFreshclamLogLine(QByteArray line, QBuffer *buffer, qint64 *ts, QString *msg, bool *matched);
    qint64 initializeEventsGeneralTableWidget(qint64 page);
    qint64 initializeEventsFoundTableWidget(qint64 page, bool reset_position = true);
    qint64 initializeEventsQuarantinedTableWidget(qint64 page);
    qint64 initializeMessagesTableWidget(qint64 page);
    void initializeDateTimeLineGraphWidget(int state);
    void refreshQuarantineDirectory();
    void updateQuarantineDirectoryUi(const QString path);
    void updateDbQuarantine(QByteArray quarantine_name, quint32 timestamp, quint64 file_size, QByteArray file_name, quint8 verified);
    void updateQuaramtineCount(quint32 timestamp);
    void detectedThreatListener(QString msg, QString filename);
    void setEnabledQuarantine(bool state);
    quint64 getEntriesPerPage();
    void setScanActive(bool state);
    void initScanProcess(QStringList listWidgetToStringList);
    void processReadyRead();
    void queue_up();
    void removeScheduleItemAt(const QString link);
    void ListerQuarantineYesClicked();
    void ListerQuarantineNoClicked();

    void on_labelScanQuickScan_linkActivated(const QString &link);
    void on_labelScanDeepScan_linkActivated(const QString &link);
    void on_labelUpdateClickUpdateDefs_linkActivated(const QString &link);
    void on_labelSetupAccessPrefs_linkActivated(const QString &link);
    void on_labelNumBlockedAttacksVal_linkActivated(const QString &link);
    void on_labelHelpTitleSubtitle_linkActivated(const QString &link);
    void on_pushButtonEventGeneralPageBack_clicked();
    void on_pushButtonEventGeneralPageForward_clicked();
    void on_pushButtonEventGeneralPageBegining_clicked();
    void on_pushButtonEventGeneralPageEnd_clicked();
    void on_pushButtonEventFoundPageBack_clicked();
    void on_pushButtonEventFoundPageForward_clicked();
    void on_pushButtonEventFoundPageBegining_clicked();
    void on_pushButtonEventFoundPageEnd_clicked();
    void on_pushButtonEventQuarantinedPageBack_clicked();
    void on_pushButtonEventQuarantinedPageForward_clicked();
    void on_pushButtonEventQuarantinedPageBegining_clicked();
    void on_pushButtonEventQuarantinedPageEnd_clicked();
    void on_pushButtonMessagesPageBack_clicked();
    void on_pushButtonMessagesPageForward_clicked();
    void on_pushButtonMessagesPageBegining_clicked();
    void on_pushButtonMessagesPageEnd_clicked();
    void on_pushButtonQuarantineDelete_clicked();
    void on_pushButtonQuarantineUnQuarantine_clicked();
    void on_pushButtonSchedule_clicked();

    void on_pushButtonGraphsFileScansXscaleup_clicked();
    void on_pushButtonGraphsFileScansXscaledown_clicked();
    void on_pushButtonGraphsFileScansXshiftup_clicked();
    void on_pushButtonGraphsFileScansXshiftdown_clicked();
    void on_pushButtonGraphsFileScansResetGraph_clicked();

    void on_pushButtonGraphsFileFoundXscaleup_clicked();
    void on_pushButtonGraphsFileFoundXscaledown_clicked();
    void on_pushButtonGraphsFileFoundXshiftup_clicked();
    void on_pushButtonGraphsFileFoundXshiftdown_clicked();
    void on_pushButtonGraphsFileFoundResetGraph_clicked();

    void on_pushButtonGraphsFileQuarantineXscaleup_clicked();
    void on_pushButtonGraphsFileQuarantineXscaledown_clicked();
    void on_pushButtonGraphsFileQuarantineXshiftup_clicked();
    void on_pushButtonGraphsFileQuarantineXshiftdown_clicked();
    void on_pushButtonGraphsFileQuarantineResetGraph_clicked();

    void timerSlot();

    void ckScheduledScans();
    bool ckScheduledScanMatch(const int time_val, const bool ok1, const int num1, const bool ok2, const int num2, const bool ok3, const int num3);

    void actionExit();
    void statusSetError();
    void statusSetWarn();
    void statusSetOk();
    void statusSetGrey();
    void updateSetError();
    void updateSetWarn();
    void updateSetOk();
    void updateSetGrey();

signals:
    void detectedThreatFound(QString msg, QString filename = "");
    void sigProcessReadyRead(QByteArray buffer);
    void initializeFreelanceScan(bool active, QStringList stringlist);
    void addExclusionClamdconf(QByteArray exclude_filename);

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void setValDB(QString key, QString val);
    void aboutToQuit();
    void procKill();
    void threadKill();

private:
    Ui::MainWindow *ui;
    QAction *statusAction;
    QAction *scanAction;
    QAction *updateAction;
    QAction *historyAction;
    QAction *aboutAction;
    QAction *quitAction;

    QTimer *timer;
    bool onNextCycle;
    QTimer *timerSchedule;
    QLocalSocket *localSocket;
    QString localSocketFilename;
    ClamavDNSDataStruct cDns;
    ClamavDefHeader dailyDefHeader;
    ClamavDefHeader mainDefHeader;
    ClamavDefHeader byteDefHeader;
    QString dbFileLocation;
    QSqlDatabase db;
    qint64 lastTimestampClamdLogFile;
    quint64 intEventGeneralPageNumber;
    quint64 intEventFoundPageNumber;
    quint64 intEventQuarantinedPageNumber;
    quint64 intMessagesPageNumber;

    QVector<QThread*> threads_list;
    QQueue<Quarantiner*> queue;

    QList<ScheduleItem *> schedule;

    AboutDialog *about = Q_NULLPTR;
    ConfigureDialogCurrent *config = Q_NULLPTR;
    ScanDialog *scanDialog = Q_NULLPTR;
    ListerQuarantine *listerQuarantine = Q_NULLPTR;

    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;

    bool isScanActive;
    bool refreshFoundTableOnUpdate;
    QProcess *p = Q_NULLPTR;
    QFileSystemWatcher *quarantineDirectoryWatcher;

    qint32 graphs_scaned_xscale = 0;
    qreal graphs_scaned_xshift = 0;
    qint32 graphs_found_xscale = 0;
    qreal graphs_found_xshift = 0;
    qint32 graphs_quarantine_xscale = 0;
    qreal graphs_quarantine_xshift = 0;

    QString getClamdLocalSocketname();
    QString getClamdLogFileName();
    QString getClamdUpdateLogFileName();
    QString getClamdDatabaseDirectoryName();
    QString getValDB(QString key);
    bool setUID();
    bool requestUpdatedcDns();
    bool checkDefsHeaderDaily();
    bool checkDefsHeaderMain();
    bool checkDefsHeaderByte();
    void ckLogfileDisplay();
    QStringList ckExistsOnFs();
    void ckProc(int *pidClamd = Q_NULLPTR, int *pidFreshclam = Q_NULLPTR, int *pidClamonacc = Q_NULLPTR);
    quint32 clamdscanVersion(QByteArray *clamdscan_ver);
#ifdef CLAMONE_COUNT_ITEMS_SCANNED
    void countTotalScanItems(const QStringList items, quint64 *count = Q_NULLPTR);
    void countScanItem(const QString item, quint64 *count = Q_NULLPTR);
#endif //CLAMONE_COUNT_ITEMS_SCANNED
    quint8 getQuarantineFileStatus(QString quarantine_name);
    bool getQuarantineInfo(QString quarantine_name, quint32 *timestamp, quint64 *file_size, QByteArray *file_name);
    void setErrorAVReason(QString in);
    void updateNewEventsCount();
    void rand_bytes(quint32 len, QByteArray *out);
    void new_quarantiner(QByteArray in);
    void add_new_schedule(bool enable, QString schedule_name, QString schedule_minute, QString schedule_hour, QString schedule_day_month, QString schedule_month, QString schedule_day_week, QStringList schedule_stringlist);
    void add_new_schedule();
    void schedule_detected_change();
    void parseScheduleDayWeek(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3);
    void parseScheduleMonth(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3);
    void parseScheduleDayMonth(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3);
    void parseScheduleHours(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3);
    void parseScheduleMinutes(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3);
    void parseScheduleBaseTime(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3, int limit_min, int limit_max);
    void errorMsg(QString msg = "", bool enable_exit = true);
    void exitProgram(int ret = 0);

    void *handle;
    PROCTAB* (*openproc_p)(int, ...);
    proc_t* (*readproc_p)(PROCTAB *, proc_t *);
    void (*closeproc_p)(PROCTAB*);

protected:
    void closeEvent(QCloseEvent *event) override;
};

#endif // MAINWINDOW_H

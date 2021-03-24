#ifndef CONFIGUREDIALOG_H
#define CONFIGUREDIALOG_H

#include <QObject>
#include <QFile>
#include <QDialog>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QStackedWidget>
#include <QSpacerItem>
#include <QWidget>
#include <QProcess>
#include <QTabWidget>
#include <QScrollArea>
#include <QIcon>

#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QCheckBox>
#include <QScrollBar>

#include <QDebug>

#include "qstringlistwidget.h"
#include "qlistspinboxwidget.h"
#include "LineEditPlug.h"
#include "CheckBoxPlug.h"
#include "SpinBoxPlug.h"
#include "StringListWidgetPlug.h"
#include "ComboBoxPlug.h"
#include "ListSpinBoxWidgetPlug.h"

#include "confs.h"

class ConfigureDialog : public QDialog
{
    Q_OBJECT

private slots:
    void listen_pushButtonCancel_clicked();
    void listen_pushButtonApply_clicked();
    void listen_pushButtonOk_clicked();
    void listen_pushButtonReloadClamAV_clicked();

signals:
    void setValDB(QString key, QString val);
    void refreshEventGeneral(qint64 page);
    void refreshEventFound(qint64 page, bool reset_position);
    void refreshEventQuarantined(qint64 page);
    void refreshMessages(qint64 page);
    void refreshQuarantineDirectory();
    void setEnabledQuarantine(bool state);

public:
    ConfigureDialog(QString dbLoc, QWidget *parent);
    void setVersion(quint32 version);
    void updateClamdconfLoc(QString loc);
    void updateFreshclamconfLoc(QString loc);
    void updateEntriesPerPage(QString loc);
    void updateMonitorOnAccess(bool state);
    void updateEnableQuarantine(bool state);
    void updateMaximumQuarantineFileSize(quint64 size);
    void updateLocationQuarantineFileDirectory(QString loc);

public slots:
    bool fileClamdconfToUI(QString filename);
    bool fileFreshclamconfToUI(QString filename);
    void fileUiToClamdconf(QByteArray *out);
    void fileUiToFreshclamconf(QByteArray *out);
    void addExclusionClamdconf(QByteArray exclude_filename);

private:
    void options_tab_init();
    void options_basics_tab_init();
    void clamd_tab_init();
    void clamd_netsock_tab_init();
    void clamd_logs_tab_init();
    void clamd_parameters_tab_init();
    void clamd_filesys_tab_init();
    void clamd_scanning_tab_init();
    void clamd_alerts_tab_init();
    void clamd_onaccess_tab_init();
    void clamd_prelude_tab_init();
    void freshclam_tab_init();
    void freshclam_logs_tab_init();
    void freshclam_connect_tab_init();
    void freshclam_databases_tab_init();
    void freshclam_http_tab_init();
    void freshclam_misc_tab_init();

    void disableAllClamdconf();
    void disableAllFreshclamconf();
    //int toClamInt(QString in);
    //QString toClamInt(int in);
    bool matchBoolTrue(QRegularExpression r, QByteArray l);
    bool matchBoolFalse(QRegularExpression r, QByteArray l);
    bool parseBoolUi(QString part, QByteArray l, QCheckBox *cbEnable, QCheckBox *cb);

    QByteArray oldClamdconf;
    QByteArray oldErrClamdconf;
    QByteArray oldFreshclamconf;
    QByteArray oldErrFreshclamconf;

    QListWidget *listWidgetMain = Q_NULLPTR;
    QStackedWidget *stackedWidget = Q_NULLPTR;
    QPushButton *pushButtonReloadClamav = Q_NULLPTR;
    QPushButton *pushButtonApply = Q_NULLPTR;
    QPushButton *pushButtonCancel = Q_NULLPTR;
    QPushButton *pushButtonOk = Q_NULLPTR;
    QWidget *pageOptions = Q_NULLPTR;
    QWidget *pageClamd = Q_NULLPTR;
    QWidget *pageFreshclam = Q_NULLPTR;

    //Options -> Basics
    QTabWidget *tabWidgetOptions = Q_NULLPTR;
    QWidget *tabBasics = Q_NULLPTR;
    QScrollArea *tabBasicScrollArea = Q_NULLPTR;
    QWidget *tabBasicScrollAreaWidget = Q_NULLPTR;

    //Basics
    QHBoxLayout *horizontalLayoutLocationOfClamonedb = Q_NULLPTR;
    QLabel *labelLocationOfClamonedb = Q_NULLPTR;
    QLineEdit *lineEditLocationOfClamonedb = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutLocationOfClamdconf = Q_NULLPTR;
    QLabel *labelLocationOfClamdconf = Q_NULLPTR;
    QLineEdit *lineEditLocationOfClamdconf = Q_NULLPTR;
    QPushButton *pushButtonLocationOfClamdconf = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutLocationOfFreshclamconf = Q_NULLPTR;
    QLabel *labelLocationOfFreshclamconf = Q_NULLPTR;
    QLineEdit *lineEditLocationOfFreshclamconf = Q_NULLPTR;
    QPushButton *pushButtonLocationOfFreshclamconf = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutEntriesPerPage = Q_NULLPTR;
    QLabel *labelEntriesPerPage = Q_NULLPTR;
    QSpinBox *spinBoxEntriesPerPage = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutMonitorOnAccess = Q_NULLPTR;
    QLabel *labelMonitorOnAccess = Q_NULLPTR;
    QCheckBox *checkBoxMonitorOnAccess = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutEnableClamOneQuarantine = Q_NULLPTR;
    QLabel *labelEnableClamOneQuarantine = Q_NULLPTR;
    QCheckBox *checkBoxEnableClamOneQuarantine = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutMaximumFileSizeToQuarantine = Q_NULLPTR;
    QLabel *labelMaximumFileSizeToQuarantine = Q_NULLPTR;
    QSpinBox *spinBoxMaximumFileSizeToQuarantine = Q_NULLPTR;

    QHBoxLayout *horizontalLayoutLocationOfQuarantineFilesDirectory = Q_NULLPTR;
    QLabel *labelLocationOfQuarantineFilesDirectory = Q_NULLPTR;
    QLineEdit *lineEditLocationOfQuarantineFilesDirectory = Q_NULLPTR;
    QPushButton *pushButtonLocationOfQuarantineFilesDirectory = Q_NULLPTR;

    //Clamd -> NetSock
    QTabWidget *tabWidgetClamd = Q_NULLPTR;
    QWidget *tabNetSock = Q_NULLPTR;
    QScrollArea *tabNetSockScrollArea = Q_NULLPTR;
    QWidget *tabNetSockScrollAreaWidget = Q_NULLPTR;
    //Clamd -> Logs
    QWidget *tabLogs = Q_NULLPTR;
    QScrollArea *tabLogsScrollArea = Q_NULLPTR;
    QWidget *tabLogsScrollAreaWidget = Q_NULLPTR;
    //Clamd -> Parameters
    QWidget *tabParameters = Q_NULLPTR;
    QScrollArea *tabParametersScrollArea = Q_NULLPTR;
    QWidget *tabParametersScrollAreaWidget = Q_NULLPTR;
    //Clamd -> FileSys
    QWidget *tabFileSys = Q_NULLPTR;
    QScrollArea *tabFileSysScrollArea = Q_NULLPTR;
    QWidget *tabFileSysScrollAreaWidget = Q_NULLPTR;
    //Clamd -> Scanning
    QWidget *tabScanning = Q_NULLPTR;
    QScrollArea *tabScanningScrollArea = Q_NULLPTR;
    QWidget *tabScanningScrollAreaWidget = Q_NULLPTR;
    //Clamd -> Alerts
    QWidget *tabAlerts = Q_NULLPTR;
    QScrollArea *tabAlertsScrollArea = Q_NULLPTR;
    QWidget *tabAlertsScrollAreaWidget = Q_NULLPTR;
    //Clamd -> OnAccess
    QWidget *tabOnAccess = Q_NULLPTR;
    QScrollArea *tabOnAccessScrollArea = Q_NULLPTR;
    QWidget *tabOnAccessScrollAreaWidget = Q_NULLPTR;
    //Clamd -> Prelude
    QWidget *tabPrelude = Q_NULLPTR;
    QScrollArea *tabPreludeScrollArea = Q_NULLPTR;
    QWidget *tabPreludeScrollAreaWidget = Q_NULLPTR;

    //NetSock
    LineEditPlug *cntLocalSocket = Q_NULLPTR;
    LineEditPlug *cntLocalSocketGroup = Q_NULLPTR;
    LineEditPlug *cntLocalSocketMode = Q_NULLPTR;
    CheckBoxPlug *cntFixStaleSocket = Q_NULLPTR;
    SpinBoxPlug *cntTCPSocket = Q_NULLPTR;
    StringListWidgetPlug *cntTCPAddr = Q_NULLPTR;
    SpinBoxPlug *cntMaxConnectionQueueLength = Q_NULLPTR;
    SpinBoxPlug *cntStreamMaxLength = Q_NULLPTR;
    SpinBoxPlug *cntStreamMinPort = Q_NULLPTR;
    SpinBoxPlug *cntStreamMaxPort = Q_NULLPTR;
    SpinBoxPlug *cntMaxThreads = Q_NULLPTR;
    SpinBoxPlug *cntReadTimeout = Q_NULLPTR;
    SpinBoxPlug *cntCommandReadTimeout = Q_NULLPTR;
    SpinBoxPlug *cntSendBufTimeout = Q_NULLPTR;
    SpinBoxPlug *cntMaxQueue = Q_NULLPTR;
    SpinBoxPlug *cntIdleTimeout = Q_NULLPTR;
    StringListWidgetPlug *cntExcludePath = Q_NULLPTR;
    CheckBoxPlug *cntConcurrentDatabaseReload = Q_NULLPTR;
    CheckBoxPlug *cntStructuredCCOnly = Q_NULLPTR;

    //Logs
    LineEditPlug *cntLogFile = Q_NULLPTR;
    CheckBoxPlug *cntLogFileUnlock = Q_NULLPTR;
    SpinBoxPlug *cntLogFileMaxSize = Q_NULLPTR;
    CheckBoxPlug *cntLogTime = Q_NULLPTR;
    CheckBoxPlug *cntLogClean = Q_NULLPTR;
    CheckBoxPlug *cntLogSyslog = Q_NULLPTR;
    LineEditPlug *cntLogFacility = Q_NULLPTR;
    CheckBoxPlug *cntLogVerbose = Q_NULLPTR;
    CheckBoxPlug *cntLogRotate = Q_NULLPTR;

    //Parameters
    CheckBoxPlug *cntExtendedDetectionInfo = Q_NULLPTR;
    LineEditPlug *cntPidFile = Q_NULLPTR;
    LineEditPlug *cntTemporaryDirectory = Q_NULLPTR;
    LineEditPlug *cntDatabaseDirectory = Q_NULLPTR;
    CheckBoxPlug *cntOfficialDatabaseOnly = Q_NULLPTR;

    //FileSys
    SpinBoxPlug *cntMaxDirectoryRecursion = Q_NULLPTR;
    CheckBoxPlug *cntFollowDirectorySymlinks = Q_NULLPTR;
    CheckBoxPlug *cntFollowFileSymlinks = Q_NULLPTR;
    CheckBoxPlug *cntCrossFilesystems = Q_NULLPTR;
    SpinBoxPlug *cntSelfCheck = Q_NULLPTR;
    CheckBoxPlug *cntDisableCache = Q_NULLPTR;
    LineEditPlug *cntVirusEvent = Q_NULLPTR;
    CheckBoxPlug *cntExitOnOOM = Q_NULLPTR;
    CheckBoxPlug *cntAllowAllMatchScan = Q_NULLPTR;
    CheckBoxPlug *cntForeground = Q_NULLPTR;
    CheckBoxPlug *cntDebug = Q_NULLPTR;
    CheckBoxPlug *cntLeaveTemporaryFiles = Q_NULLPTR;

    //Scanning
    LineEditPlug *cntUser = Q_NULLPTR;
    CheckBoxPlug *cntBytecode = Q_NULLPTR;
    ComboBoxPlug *cntBytecodeSecurity = Q_NULLPTR;
    SpinBoxPlug *cntBytecodeTimeout = Q_NULLPTR;
    CheckBoxPlug *cntBytecodeUnsigned = Q_NULLPTR;
    ComboBoxPlug *cntBytecodeMode = Q_NULLPTR;
    CheckBoxPlug *cntDetectPUA = Q_NULLPTR;
    StringListWidgetPlug *cntExcludePUA = Q_NULLPTR;
    StringListWidgetPlug *cntIncludePUA = Q_NULLPTR;
    CheckBoxPlug *cntScanPE = Q_NULLPTR;
    CheckBoxPlug *cntScanELF = Q_NULLPTR;
    CheckBoxPlug *cntScanMail = Q_NULLPTR;
    CheckBoxPlug *cntScanPartialMessages = Q_NULLPTR;
    CheckBoxPlug *cntPhishingSignatures = Q_NULLPTR;
    CheckBoxPlug *cntPhishingScanURLs = Q_NULLPTR;
    CheckBoxPlug *cntHeuristicAlerts = Q_NULLPTR;
    CheckBoxPlug *cntHeuristicScanPrecedence = Q_NULLPTR;
    CheckBoxPlug *cntStructuredDataDetection = Q_NULLPTR;
    SpinBoxPlug *cntStructuredMinCreditCardCount = Q_NULLPTR;
    SpinBoxPlug *cntStructuredMinSSNCount = Q_NULLPTR;
    CheckBoxPlug *cntStructuredSSNFormatNormal = Q_NULLPTR;
    CheckBoxPlug *cntStructuredSSNFormatStripped = Q_NULLPTR;
    CheckBoxPlug *cntScanHTML = Q_NULLPTR;
    CheckBoxPlug *cntScanOLE2 = Q_NULLPTR;
    CheckBoxPlug *cntScanPDF = Q_NULLPTR;
    CheckBoxPlug *cntScanSWF = Q_NULLPTR;
    CheckBoxPlug *cntScanXMLDOCS = Q_NULLPTR;
    CheckBoxPlug *cntScanHWP3 = Q_NULLPTR;
    CheckBoxPlug *cntScanArchive = Q_NULLPTR;

    //Alerts
    CheckBoxPlug *cntAlertBrokenExecutables = Q_NULLPTR;
    CheckBoxPlug *cntAlertEncrypted = Q_NULLPTR;
    CheckBoxPlug *cntAlertEncryptedArchive = Q_NULLPTR;
    CheckBoxPlug *cntAlertEncryptedDoc = Q_NULLPTR;
    CheckBoxPlug *cntAlertOLE2Macros = Q_NULLPTR;
    CheckBoxPlug *cntAlertExceedsMax = Q_NULLPTR;
    CheckBoxPlug *cntAlertPhishingSSLMismatch = Q_NULLPTR;
    CheckBoxPlug *cntAlertPhishingCloak = Q_NULLPTR;
    CheckBoxPlug *cntAlertPartitionIntersection = Q_NULLPTR;
    CheckBoxPlug *cntForceToDisk = Q_NULLPTR;
    SpinBoxPlug *cntMaxScanTime = Q_NULLPTR;
    SpinBoxPlug *cntMaxScanSize = Q_NULLPTR;
    SpinBoxPlug *cntMaxFileSize = Q_NULLPTR;
    SpinBoxPlug *cntMaxRecursion = Q_NULLPTR;
    SpinBoxPlug *cntMaxFiles = Q_NULLPTR;
    SpinBoxPlug *cntMaxEmbeddedPE = Q_NULLPTR;
    SpinBoxPlug *cntMaxHTMLNormalize = Q_NULLPTR;
    SpinBoxPlug *cntMaxHTMLNoTags = Q_NULLPTR;
    SpinBoxPlug *cntMaxScriptNormalize = Q_NULLPTR;
    SpinBoxPlug *cntMaxZipTypeRcg = Q_NULLPTR;
    SpinBoxPlug *cntMaxPartitions = Q_NULLPTR;
    SpinBoxPlug *cntMaxIconsPE = Q_NULLPTR;
    SpinBoxPlug *cntMaxRecHWP3 = Q_NULLPTR;
    SpinBoxPlug *cntPCREMatchLimit = Q_NULLPTR;
    SpinBoxPlug *cntPCRERecMatchLimit = Q_NULLPTR;
    SpinBoxPlug *cntPCREMaxFileSize = Q_NULLPTR;

    //OnAccess
    CheckBoxPlug *cntScanOnAccess = Q_NULLPTR;
    StringListWidgetPlug *cntOnAccessMountPath = Q_NULLPTR;
    StringListWidgetPlug *cntOnAccessIncludePath = Q_NULLPTR;
    StringListWidgetPlug *cntOnAccessExcludePath = Q_NULLPTR;
    CheckBoxPlug *cntOnAccessExcludeRootUID = Q_NULLPTR;
    ListSpinBoxWidgetPlug *cntOnAccessExcludeUID = Q_NULLPTR;
    StringListWidgetPlug *cntOnAccessExcludeUname = Q_NULLPTR;
    SpinBoxPlug *cntOnAccessMaxFileSize = Q_NULLPTR;
    CheckBoxPlug *cntOnAccessDisableDDD = Q_NULLPTR;
    CheckBoxPlug *cntOnAccessPrevention = Q_NULLPTR;
    CheckBoxPlug *cntOnAccessExtraScanning = Q_NULLPTR;
    SpinBoxPlug *cntOnAccessCurlTimeout = Q_NULLPTR;
    SpinBoxPlug *cntOnAccessMaxThreads = Q_NULLPTR;
    SpinBoxPlug *cntOnAccessRetryAttempts = Q_NULLPTR;
    CheckBoxPlug *cntOnAccessDenyOnError = Q_NULLPTR;
    CheckBoxPlug *cntDisableCertCheck = Q_NULLPTR;
    //Dep
    CheckBoxPlug *cntClamAuth = Q_NULLPTR;
    StringListWidgetPlug *cntClamukoExcludePath = Q_NULLPTR;
    ListSpinBoxWidgetPlug *cntClamukoExcludeUID = Q_NULLPTR;
    StringListWidgetPlug *cntClamukoIncludePath = Q_NULLPTR;
    SpinBoxPlug *cntClamukoMaxFileSize = Q_NULLPTR;
    SpinBoxPlug *cntClamukoScannerCount = Q_NULLPTR;
    CheckBoxPlug *cntClamukoScanOnAccess = Q_NULLPTR;
    CheckBoxPlug *cntClamukoScanOnClose = Q_NULLPTR;
    CheckBoxPlug *cntClamukoScanOnExec = Q_NULLPTR;
    CheckBoxPlug *cntClamukoScanOnOpen = Q_NULLPTR;

    //Prelude
    CheckBoxPlug *cntPreludeEnable = Q_NULLPTR;
    LineEditPlug *cntPreludeAnalyzerName = Q_NULLPTR;

    //Deprecated
    CheckBoxPlug *cntAllowSupplementaryGroups = Q_NULLPTR;
    CheckBoxPlug *cntDetectBrokenExecutables = Q_NULLPTR;
    CheckBoxPlug *cntMailFollowURLs = Q_NULLPTR;
    CheckBoxPlug *cntStatsEnabled = Q_NULLPTR;
    LineEditPlug *cntStatsHostID = Q_NULLPTR;
    CheckBoxPlug *cntStatsPEDisabled = Q_NULLPTR;
    SpinBoxPlug *cntStatsTimeout = Q_NULLPTR;
    CheckBoxPlug *cntAlgorithmicDetection = Q_NULLPTR;
    CheckBoxPlug *cntArchiveBlockEncrypted = Q_NULLPTR;
    CheckBoxPlug *cntBlockMax = Q_NULLPTR;
    CheckBoxPlug *cntOLE2BlockMacros = Q_NULLPTR;
    CheckBoxPlug *cntPartitionIntersection = Q_NULLPTR;
    CheckBoxPlug *cntPhishingAlwaysBlockCloak = Q_NULLPTR;
    CheckBoxPlug *cntPhishingAlwaysBlockSSLMismatch = Q_NULLPTR;

    //Freshclam -> Logs
    QTabWidget *tabWidgetFreshclam = Q_NULLPTR;
    QWidget *tabFreshLogs = Q_NULLPTR;
    QScrollArea *tabFreshLogsScrollArea = Q_NULLPTR;
    QWidget *tabFreshLogsScrollAreaWidget = Q_NULLPTR;
    //Freshclam -> Connect
    QWidget *tabFreshConnect = Q_NULLPTR;
    QScrollArea *tabFreshConnectScrollArea = Q_NULLPTR;
    QWidget *tabFreshConnectScrollAreaWidget = Q_NULLPTR;
    //Freshclam -> Databases
    QWidget *tabFreshDatabases = Q_NULLPTR;
    QScrollArea *tabFreshDatabasesScrollArea = Q_NULLPTR;
    QWidget *tabFreshDatabasesScrollAreaWidget = Q_NULLPTR;
    //Freshclam -> HTTP
    QWidget *tabFreshHTTP = Q_NULLPTR;
    QScrollArea *tabFreshHTTPScrollArea = Q_NULLPTR;
    QWidget *tabFreshHTTPScrollAreaWidget = Q_NULLPTR;
    //Freshclam -> Misc
    QWidget *tabFreshMisc = Q_NULLPTR;
    QScrollArea *tabFreshMiscScrollArea = Q_NULLPTR;
    QWidget *tabFreshMiscScrollAreaWidget = Q_NULLPTR;

    //FreshLogs
    SpinBoxPlug *cntFreshLogFileMaxSize = Q_NULLPTR;
    CheckBoxPlug *cntFreshLogTime = Q_NULLPTR;
    CheckBoxPlug *cntFreshLogSyslog = Q_NULLPTR;
    LineEditPlug *cntFreshLogFacility = Q_NULLPTR;
    CheckBoxPlug *cntFreshLogVerbose = Q_NULLPTR;
    CheckBoxPlug *cntFreshLogRotate = Q_NULLPTR;

    //FreshConnect
    LineEditPlug *cntFreshPidFile = Q_NULLPTR;
    LineEditPlug *cntFreshDatabaseDirectory = Q_NULLPTR;
    CheckBoxPlug *cntFreshForeground = Q_NULLPTR;
    CheckBoxPlug *cntFreshDebug = Q_NULLPTR;
    LineEditPlug *cntFreshUpdateLogFile = Q_NULLPTR;
    LineEditPlug *cntFreshDatabaseOwner = Q_NULLPTR;
    SpinBoxPlug *cntFreshChecks = Q_NULLPTR;
    LineEditPlug *cntFreshDNSDatabaseInfo = Q_NULLPTR;
    StringListWidgetPlug *cntFreshDatabaseMirror = Q_NULLPTR;
    StringListWidgetPlug *cntFreshPrivateMirror = Q_NULLPTR;
    SpinBoxPlug *cntFreshMaxAttempts = Q_NULLPTR;
    CheckBoxPlug *cntFreshScriptedUpdates = Q_NULLPTR;

    //FreshDatabases
    CheckBoxPlug *cntFreshTestDatabases = Q_NULLPTR;
    CheckBoxPlug *cntFreshCompressLocalDatabase = Q_NULLPTR;
    StringListWidgetPlug *cntFreshExtraDatabase = Q_NULLPTR;
    StringListWidgetPlug *cntFreshExcludeDatabase = Q_NULLPTR;
    StringListWidgetPlug *cntFreshDatabaseCustomURL = Q_NULLPTR;

    //FreshHTTP
    LineEditPlug *cntFreshHTTPProxyServer = Q_NULLPTR;
    SpinBoxPlug *cntFreshHTTPProxyPort = Q_NULLPTR;
    LineEditPlug *cntFreshHTTPProxyUsername = Q_NULLPTR;
    LineEditPlug *cntFreshHTTPProxyPassword = Q_NULLPTR;
    LineEditPlug *cntFreshHTTPUserAgent = Q_NULLPTR;

    //FreshMisc
    LineEditPlug *cntFreshNotifyClamd = Q_NULLPTR;
    LineEditPlug *cntFreshOnUpdateExecute = Q_NULLPTR;
    LineEditPlug *cntFreshOnErrorExecute = Q_NULLPTR;
    LineEditPlug *cntFreshOnOutdatedExecute = Q_NULLPTR;
    LineEditPlug *cntFreshLocalIPAddress = Q_NULLPTR;
    SpinBoxPlug *cntFreshConnectTimeout = Q_NULLPTR;
    SpinBoxPlug *cntFreshReceiveTimeout = Q_NULLPTR;
    CheckBoxPlug *cntFreshSafeBrowsing = Q_NULLPTR;
    CheckBoxPlug *cntFreshBytecode = Q_NULLPTR;

    //FreshDeprecated
    CheckBoxPlug *cntFreshAllowSupplementaryGroups = Q_NULLPTR;
    LineEditPlug *cntFreshDetectionStatsCountry = Q_NULLPTR;
    LineEditPlug *cntFreshDetectionStatsHostID = Q_NULLPTR;
    CheckBoxPlug *cntFreshStatsEnabled = Q_NULLPTR;
    LineEditPlug *cntFreshStatsHostID = Q_NULLPTR;
    SpinBoxPlug *cntFreshStatsTimeout = Q_NULLPTR;
    LineEditPlug *cntFreshSubmitDetectionStats = Q_NULLPTR;
};

#endif // CONFIGUREDIALOG_H

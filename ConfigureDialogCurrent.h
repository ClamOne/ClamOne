#ifndef CONFIGUREDIALOG_H
#define CONFIGUREDIALOG_H

#include <QDialog>
#include <QFileDialog>
#include <QCloseEvent>
#include <QMessageBox>
#include <QCheckBox>
#include <QScrollBar>
#include <QProcess>

#include <QDebug>

#include "confs.h"

namespace Ui {
class ConfigureDialogCurrent;
}

class ConfigureDialogCurrent : public QDialog
{
    Q_OBJECT

private slots:
    void on_pushButtonReloadClamav_clicked();
    void on_pushButtonApply_clicked();
    void on_pushButtonOk_clicked();
    void on_pushButtonCancel_clicked();
    void on_pushButtonClamconfFileDialog_clicked();
    void on_pushButtonFreshclamconfFileDialog_clicked();

    //Clamd.conf
    void on_checkBoxPreludeEnable_stateChanged(int state);
    void on_checkBoxLogFileUnlock_stateChanged(int state);
    void on_checkBoxLogTime_stateChanged(int state);
    void on_checkBoxLogClean_stateChanged(int state);
    void on_checkBoxLogSyslog_stateChanged(int state);
    void on_checkBoxLogVerbose_stateChanged(int state);
    void on_checkBoxLogRotate_stateChanged(int state);
    void on_checkBoxExtendedDetectionInfo_stateChanged(int state);
    void on_checkBoxOfficialDatabaseOnly_stateChanged(int state);
    void on_checkBoxFixStaleSocket_stateChanged(int state);
    void on_checkBoxFollowDirectorySymlinks_stateChanged(int state);
    void on_checkBoxFollowFileSymlinks_stateChanged(int state);
    void on_checkBoxCrossFilesystems_stateChanged(int state);
    void on_checkBoxDisableCache_stateChanged(int state);
    void on_checkBoxExitOnOOM_stateChanged(int state);
    void on_checkBoxAllowAllMatchScan_stateChanged(int state);
    void on_checkBoxForeground_stateChanged(int state);
    void on_checkBoxDebug_stateChanged(int state);
    void on_checkBoxLeaveTemporaryFiles_stateChanged(int state);
    void on_checkBoxBytecode_stateChanged(int state);
    void on_checkBoxBytecodeUnsigned_stateChanged(int state);
    void on_checkBoxDetectPUA_stateChanged(int state);
    void on_checkBoxScanPE_stateChanged(int state);
    void on_checkBoxScanELF_stateChanged(int state);
    void on_checkBoxScanMail_stateChanged(int state);
    void on_checkBoxScanPartialMessages_stateChanged(int state);
    void on_checkBoxPhishingSignatures_stateChanged(int state);
    void on_checkBoxPhishingScanURLs_stateChanged(int state);
    void on_checkBoxHeuristicAlerts_stateChanged(int state);
    void on_checkBoxHeuristicScanPrecedence_stateChanged(int state);
    void on_checkBoxStructuredDataDetection_stateChanged(int state);
    void on_checkBoxStructuredSSNFormatNormal_stateChanged(int state);
    void on_checkBoxStructuredSSNFormatStripped_stateChanged(int state);
    void on_checkBoxScanHTML_stateChanged(int state);
    void on_checkBoxScanOLE2_stateChanged(int state);
    void on_checkBoxAlertEncrypted_stateChanged(int state);
    void on_checkBoxAlertEncryptedArchive_stateChanged(int state);
    void on_checkBoxAlertEncryptedDoc_stateChanged(int state);
    void on_checkBoxAlertOLE2Macros_stateChanged(int state);
    void on_checkBoxAlertExceedsMax_stateChanged(int state);
    void on_checkBoxAlertPhishingSSLMismatch_stateChanged(int state);
    void on_checkBoxAlertPhishingCloak_stateChanged(int state);
    void on_checkBoxAlertPartitionIntersection_stateChanged(int state);
    void on_checkBoxScanPDF_stateChanged(int state);
    void on_checkBoxScanSWF_stateChanged(int state);
    void on_checkBoxScanXMLDOCS_stateChanged(int state);
    void on_checkBoxScanArchive_stateChanged(int state);
    void on_checkBoxOnAccessExcludeRootUID_stateChanged(int state);
    void on_checkBoxOnAccessDisableDDD_stateChanged(int state);
    void on_checkBoxOnAccessPrevention_stateChanged(int state);
    void on_checkBoxOnAccessExtraScanning_stateChanged(int state);
    void on_checkBoxOnAccessDenyOnError_stateChanged(int state);
    void on_checkBoxDisableCertCheck_stateChanged(int state);
    void on_checkBoxScanOnAccess_stateChanged(int state);

    //Options
    void on_checkBoxMonitorOnAccess_stateChanged(int state);
    void on_checkBoxEnableClamOneQuarantine_stateChanged(int state);

    //Freshclam.conf
    void on_checkBoxFreshLogTime_stateChanged(int state);
    void on_checkBoxFreshLogSyslog_stateChanged(int state);
    void on_checkBoxFreshLogVerbose_stateChanged(int state);
    void on_checkBoxFreshLogRotate_stateChanged(int state);
    void on_checkBoxFreshForeground_stateChanged(int state);
    void on_checkBoxFreshDebug_stateChanged(int state);
    void on_checkBoxFreshScriptedUpdates_stateChanged(int state);
    void on_checkBoxFreshTestDatabases_stateChanged(int state);
    void on_checkBoxFreshCompressLocalDatabase_stateChanged(int state);
    void on_checkBoxFreshSafeBrowsing_stateChanged(int state);
    void on_checkBoxFreshBytecode_stateChanged(int state);

    //Enable Clamd.conf
    void on_checkBoxEnableLocalSocket_stateChanged(int state);
    void on_checkBoxEnableLocalSocketGroup_stateChanged(int state);
    void on_checkBoxEnableLocalSocketMode_stateChanged(int state);
    void on_checkBoxEnableFixStaleSocket_stateChanged(int state);
    void on_checkBoxEnableTCPSocket_stateChanged(int state);
    void on_checkBoxEnableTCPAddr_stateChanged(int state);
    void on_checkBoxEnableMaxConnectionQueueLength_stateChanged(int state);
    void on_checkBoxEnableStreamMaxLength_stateChanged(int state);
    void on_checkBoxEnableStreamMinPort_stateChanged(int state);
    void on_checkBoxEnableStreamMaxPort_stateChanged(int state);
    void on_checkBoxEnableMaxThreads_stateChanged(int state);
    void on_checkBoxEnableReadTimeout_stateChanged(int state);
    void on_checkBoxEnableCommandReadTimeout_stateChanged(int state);
    void on_checkBoxEnableSendBufTimeout_stateChanged(int state);
    void on_checkBoxEnableMaxQueue_stateChanged(int state);
    void on_checkBoxEnableIdleTimeout_stateChanged(int state);
    void on_checkBoxEnableExcludePath_stateChanged(int state);
    void on_checkBoxEnableLogFile_stateChanged(int state);
    void on_checkBoxEnableLogFileUnlock_stateChanged(int state);
    void on_checkBoxEnableLogFileMaxSize_stateChanged(int state);
    void on_checkBoxEnableLogTime_stateChanged(int state);
    void on_checkBoxEnableLogClean_stateChanged(int state);
    void on_checkBoxEnableLogSyslog_stateChanged(int state);
    void on_checkBoxEnableLogFacility_stateChanged(int state);
    void on_checkBoxEnableLogVerbose_stateChanged(int state);
    void on_checkBoxEnableLogRotate_stateChanged(int state);
    void on_checkBoxEnableExtendedDetectionInfo_stateChanged(int state);
    void on_checkBoxEnablePidFile_stateChanged(int state);
    void on_checkBoxEnableTemporaryDirectory_stateChanged(int state);
    void on_checkBoxEnableDatabaseDirectory_stateChanged(int state);
    void on_checkBoxEnableOfficialDatabaseOnly_stateChanged(int state);
    void on_checkBoxEnableMaxDirectoryRecursion_stateChanged(int state);
    void on_checkBoxEnableFollowDirectorySymlinks_stateChanged(int state);
    void on_checkBoxEnableFollowFileSymlinks_stateChanged(int state);
    void on_checkBoxEnableCrossFilesystems_stateChanged(int state);
    void on_checkBoxEnableSelfCheck_stateChanged(int state);
    void on_checkBoxEnableDisableCache_stateChanged(int state);
    void on_checkBoxEnableVirusEvent_stateChanged(int state);
    void on_checkBoxEnableExitOnOOM_stateChanged(int state);
    void on_checkBoxEnableAllowAllMatchScan_stateChanged(int state);
    void on_checkBoxEnableForeground_stateChanged(int state);
    void on_checkBoxEnableDebug_stateChanged(int state);
    void on_checkBoxEnableLeaveTemporaryFiles_stateChanged(int state);
    void on_checkBoxEnableUser_stateChanged(int state);
    void on_checkBoxEnableBytecode_stateChanged(int state);
    void on_checkBoxEnableBytecodeSecurity_stateChanged(int state);
    void on_checkBoxEnableBytecodeTimeout_stateChanged(int state);
    void on_checkBoxEnableBytecodeUnsigned_stateChanged(int state);
    void on_checkBoxEnableBytecodeMode_stateChanged(int state);
    void on_checkBoxEnableDetectPUA_stateChanged(int state);
    void on_checkBoxEnableExcludePUA_stateChanged(int state);
    void on_checkBoxEnableIncludePUA_stateChanged(int state);
    void on_checkBoxEnableScanPE_stateChanged(int state);
    void on_checkBoxEnableScanELF_stateChanged(int state);
    void on_checkBoxEnableScanMail_stateChanged(int state);
    void on_checkBoxEnableScanPartialMessages_stateChanged(int state);
    void on_checkBoxEnablePhishingSignatures_stateChanged(int state);
    void on_checkBoxEnablePhishingScanURLs_stateChanged(int state);
    void on_checkBoxEnableHeuristicAlerts_stateChanged(int state);
    void on_checkBoxEnableHeuristicScanPrecedence_stateChanged(int state);
    void on_checkBoxEnableStructuredDataDetection_stateChanged(int state);
    void on_checkBoxEnableStructuredMinCreditCardCount_stateChanged(int state);
    void on_checkBoxEnableStructuredMinSSNCount_stateChanged(int state);
    void on_checkBoxEnableStructuredSSNFormatNormal_stateChanged(int state);
    void on_checkBoxEnableStructuredSSNFormatStripped_stateChanged(int state);
    void on_checkBoxEnableScanHTML_stateChanged(int state);
    void on_checkBoxEnableScanOLE2_stateChanged(int state);
    void on_checkBoxEnableScanPDF_stateChanged(int state);
    void on_checkBoxEnableScanSWF_stateChanged(int state);
    void on_checkBoxEnableScanXMLDOCS_stateChanged(int state);
    void on_checkBoxEnableScanHWP3_stateChanged(int state);
    void on_checkBoxEnableScanArchive_stateChanged(int state);
    void on_checkBoxEnableAlertBrokenExecutables_stateChanged(int state);
    void on_checkBoxEnableAlertEncrypted_stateChanged(int state);
    void on_checkBoxEnableAlertEncryptedArchive_stateChanged(int state);
    void on_checkBoxEnableAlertEncryptedDoc_stateChanged(int state);
    void on_checkBoxEnableAlertOLE2Macros_stateChanged(int state);
    void on_checkBoxEnableAlertExceedsMax_stateChanged(int state);
    void on_checkBoxEnableAlertPhishingSSLMismatch_stateChanged(int state);
    void on_checkBoxEnableAlertPhishingCloak_stateChanged(int state);
    void on_checkBoxEnableAlertPartitionIntersection_stateChanged(int state);
    void on_checkBoxEnableForceToDisk_stateChanged(int state);
    void on_checkBoxEnableMaxScanTime_stateChanged(int state);
    void on_checkBoxEnableMaxScanSize_stateChanged(int state);
    void on_checkBoxEnableMaxFileSize_stateChanged(int state);
    void on_checkBoxEnableMaxRecursion_stateChanged(int state);
    void on_checkBoxEnableMaxFiles_stateChanged(int state);
    void on_checkBoxEnableMaxEmbeddedPE_stateChanged(int state);
    void on_checkBoxEnableMaxHTMLNormalize_stateChanged(int state);
    void on_checkBoxEnableMaxHTMLNoTags_stateChanged(int state);
    void on_checkBoxEnableMaxScriptNormalize_stateChanged(int state);
    void on_checkBoxEnableMaxZipTypeRcg_stateChanged(int state);
    void on_checkBoxEnableMaxPartitions_stateChanged(int state);
    void on_checkBoxEnableMaxIconsPE_stateChanged(int state);
    void on_checkBoxEnableMaxRecHWP3_stateChanged(int state);
    void on_checkBoxEnablePCREMatchLimit_stateChanged(int state);
    void on_checkBoxEnablePCRERecMatchLimit_stateChanged(int state);
    void on_checkBoxEnablePCREMaxFileSize_stateChanged(int state);
    void on_checkBoxEnableOnAccessMountPath_stateChanged(int state);
    void on_checkBoxEnableOnAccessIncludePath_stateChanged(int state);
    void on_checkBoxEnableOnAccessExcludePath_stateChanged(int state);
    void on_checkBoxEnableOnAccessExcludeRootUID_stateChanged(int state);
    void on_checkBoxEnableOnAccessExcludeUID_stateChanged(int state);
    void on_checkBoxEnableOnAccessExcludeUname_stateChanged(int state);
    void on_checkBoxEnableOnAccessMaxFileSize_stateChanged(int state);
    void on_checkBoxEnableOnAccessDisableDDD_stateChanged(int state);
    void on_checkBoxEnableOnAccessPrevention_stateChanged(int state);
    void on_checkBoxEnableOnAccessExtraScanning_stateChanged(int state);
    void on_checkBoxEnableOnAccessCurlTimeout_stateChanged(int state);
    void on_checkBoxEnableOnAccessMaxThreads_stateChanged(int state);
    void on_checkBoxEnableOnAccessRetryAttempts_stateChanged(int state);
    void on_checkBoxEnableOnAccessDenyOnError_stateChanged(int state);
    void on_checkBoxEnableDisableCertCheck_stateChanged(int state);
    void on_checkBoxEnablePreludeEnable_stateChanged(int state);
    void on_checkBoxEnableScanOnAccess_stateChanged(int state);

    //Enable Freshclam.conf
    void on_checkBoxEnableFreshLogFileMaxSize_stateChanged(int state);
    void on_checkBoxEnableFreshLogTime_stateChanged(int state);
    void on_checkBoxEnableFreshLogSyslog_stateChanged(int state);
    void on_checkBoxEnableFreshLogFacility_stateChanged(int state);
    void on_checkBoxEnableFreshLogVerbose_stateChanged(int state);
    void on_checkBoxEnableFreshLogRotate_stateChanged(int state);
    void on_checkBoxEnableFreshPidFile_stateChanged(int state);
    void on_checkBoxEnableFreshDatabaseDirectory_stateChanged(int state);
    void on_checkBoxEnableFreshForeground_stateChanged(int state);
    void on_checkBoxEnableFreshDebug_stateChanged(int state);
    void on_checkBoxEnableFreshUpdateLogFile_stateChanged(int state);
    void on_checkBoxEnableFreshDatabaseOwner_stateChanged(int state);
    void on_checkBoxEnableFreshChecks_stateChanged(int state);
    void on_checkBoxEnableFreshDNSDatabaseInfo_stateChanged(int state);
    void on_checkBoxEnableFreshDatabaseMirror_stateChanged(int state);
    void on_checkBoxEnableFreshPrivateMirror_stateChanged(int state);
    void on_checkBoxEnableFreshMaxAttempts_stateChanged(int state);
    void on_checkBoxEnableFreshScriptedUpdates_stateChanged(int state);
    void on_checkBoxEnableFreshTestDatabases_stateChanged(int state);
    void on_checkBoxEnableFreshCompressLocalDatabase_stateChanged(int state);
    void on_checkBoxEnableFreshExtraDatabase_stateChanged(int state);
    void on_checkBoxEnableFreshExcludeDatabase_stateChanged(int state);
    void on_checkBoxEnableFreshDatabaseCustomURL_stateChanged(int state);
    void on_checkBoxEnableFreshHTTPProxyServer_stateChanged(int state);
    void on_checkBoxEnableFreshHTTPProxyPort_stateChanged(int state);
    void on_checkBoxEnableFreshHTTPProxyUsername_stateChanged(int state);
    void on_checkBoxEnableFreshHTTPProxyPassword_stateChanged(int state);
    void on_checkBoxEnableFreshHTTPUserAgent_stateChanged(int state);
    void on_checkBoxEnableFreshNotifyClamd_stateChanged(int state);
    void on_checkBoxEnableFreshOnUpdateExecute_stateChanged(int state);
    void on_checkBoxEnableFreshOnErrorExecute_stateChanged(int state);
    void on_checkBoxEnableFreshOnOutdatedExecute_stateChanged(int state);
    void on_checkBoxEnableFreshLocalIPAddress_stateChanged(int state);
    void on_checkBoxEnableFreshConnectTimeout_stateChanged(int state);
    void on_checkBoxEnableFreshReceiveTimeout_stateChanged(int state);
    void on_checkBoxEnableFreshSafeBrowsing_stateChanged(int state);
    void on_checkBoxEnableFreshBytecode_stateChanged(int state);

signals:
    void setValDB(QString key, QString val);
    void refreshEventGeneral(qint64 page);
    void refreshEventFound(qint64 page, bool reset_position);
    void refreshEventQuarantined(qint64 page);
    void refreshMessages(qint64 page);
    void refreshQuarantineDirectory();
    void setEnabledQuarantine(bool state);

public:
    explicit ConfigureDialogCurrent(QString dbLoc, QWidget *parent = 0);
    ~ConfigureDialogCurrent();
    void updateClamdconfLoc(QString loc);
    void updateFreshclamconfLoc(QString loc);
    void updateEntriesPerPage(QString loc);
    void updateMonitorOnAccess(bool state);
    void updateEnableQuarantine(bool state);
    void updateMaximumQuarantineFileSize(quint64 size);
    void updateLocationQuarantineFileDirectory(QString loc);

public slots:
    //input
    bool fileClamdconfToUI(QString filename);
    bool fileFreshclamconfToUI(QString filename);
    void addExclusionClamdconf(QByteArray exclude_filename);
    //output
    bool fileUiToClamdconf(QByteArray *out);
    bool fileUiToFreshclamconf(QByteArray *out);

private:
    Ui::ConfigureDialogCurrent *ui;
    QByteArray oldClamdconf;
    QByteArray oldErrClamdconf;
    QByteArray oldFreshclamconf;
    QByteArray oldErrFreshclamconf;

    void disableAllClamdconf();
    void disableAllFreshclamconf();
    int toClamInt(QString in);
    QString toClamInt(int in);
    bool matchBoolTrue(QRegularExpression r, QByteArray l);
    bool matchBoolFalse(QRegularExpression r, QByteArray l);
    bool parseBoolUi(QString part, QByteArray l, QCheckBox *cbEnable, QCheckBox *cb);

protected:
    void closeEvent(QCloseEvent *event);
};

#endif // CONFIGUREDIALOG_H

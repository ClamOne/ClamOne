#include "ConfigureDialog.h"

ConfigureDialog::ConfigureDialog(QString dbLoc, QWidget *parent)
{
    Q_UNUSED(parent)
    setGeometry(0,0,640,480);
    setStyleSheet("QPushButton{background-color: #f0f0f0; color: #000000;}");
    QVBoxLayout *vbox01 = new QVBoxLayout();
    setLayout(vbox01);
    QHBoxLayout *horizontalLayoutMain = new QHBoxLayout();
    QHBoxLayout *horizontalLayoutOkCancel = new QHBoxLayout();
    vbox01->addLayout(horizontalLayoutMain);
    vbox01->addLayout(horizontalLayoutOkCancel);

    listWidgetMain = new QListWidget();
    listWidgetMain->setStyleSheet("QListWidget{background-color: #ffffff; color: #4a4a4a;}");
    stackedWidget = new QStackedWidget();
    stackedWidget->setStyleSheet("*:disabled{background-color: #f0f0f0; color: #9d9d9d;} *{background-color: #f0f0f0; color: #4a4a4a;}");
    connect(listWidgetMain, &QListWidget::currentRowChanged, stackedWidget, &QStackedWidget::setCurrentIndex);

    listWidgetMain->setMaximumSize(100,16777215);
    horizontalLayoutMain->addWidget(listWidgetMain);
    horizontalLayoutMain->addWidget(stackedWidget);
    listWidgetMain->addItem(tr("Options"));
    listWidgetMain->addItem(tr("Clamd"));
    listWidgetMain->addItem(tr("Freshclam"));
    listWidgetMain->addItem(tr("Snort"));
    pageOptions = new QWidget();
    pageClamd = new QWidget();
    pageFreshclam = new QWidget();
    pageSnort = new QWidget();
    stackedWidget->addWidget(pageOptions);
    stackedWidget->addWidget(pageClamd);
    stackedWidget->addWidget(pageFreshclam);
    stackedWidget->addWidget(pageSnort);

    options_tab_init();
    options_basics_tab_init();
    clamd_tab_init();
    clamd_netsock_tab_init();
    clamd_logs_tab_init();
    clamd_parameters_tab_init();
    clamd_filesys_tab_init();
    clamd_scanning_tab_init();
    clamd_alerts_tab_init();
    clamd_onaccess_tab_init();
    clamd_prelude_tab_init();
    freshclam_tab_init();
    freshclam_logs_tab_init();
    freshclam_connect_tab_init();
    freshclam_databases_tab_init();
    freshclam_http_tab_init();
    freshclam_misc_tab_init();
    snort_tab_init();
    snort_support_tab_init();

    pushButtonReloadClamav = new QPushButton(tr("Reload ClamAV"));
    pushButtonApply = new QPushButton(tr("Apply"));
    pushButtonOk = new QPushButton(tr("Ok"));
    pushButtonCancel = new QPushButton(tr("Cancel"));

    horizontalLayoutOkCancel->addStretch();
    horizontalLayoutOkCancel->addWidget(pushButtonReloadClamav);
    horizontalLayoutOkCancel->addWidget(pushButtonApply);
    horizontalLayoutOkCancel->addWidget(pushButtonOk);
    horizontalLayoutOkCancel->addWidget(pushButtonCancel);

    lineEditLocationOfClamonedb->setText(dbLoc);

    connect(pushButtonApply, &QPushButton::clicked, this, &ConfigureDialog::listen_pushButtonApply_clicked);
    connect(pushButtonCancel, &QPushButton::clicked, this, &ConfigureDialog::listen_pushButtonCancel_clicked);
    connect(pushButtonOk, &QPushButton::clicked, this, &ConfigureDialog::listen_pushButtonOk_clicked);
    connect(pushButtonReloadClamav, &QPushButton::clicked, this, &ConfigureDialog::listen_pushButtonReloadClamAV_clicked);

    connect(lineEditLocationOfClamdconf, &QLineEdit::textChanged, this, &ConfigureDialog::fileClamdconfToUI);
    connect(lineEditLocationOfFreshclamconf, &QLineEdit::textChanged, this, &ConfigureDialog::fileFreshclamconfToUI);
}

void ConfigureDialog::setVersion(quint32 version){
    setWindowTitle("Clam One - clamav "+QString::number((version&0xFF0000)>>16)+"."+QString::number((version&0xFF00)>>8)+"."+QString::number(version&0xFF));
    //clamav-0.*/shared/optparser.c clamav-0.*.0/common/optparser.c
    if(version >= QT_VERSION_CHECK(0, 97, 4) && version <= QT_VERSION_CHECK(0, 97, 8)){
        cntClamAuth->show();
        cntClamAuth->setVersion_parameter(true);
    }else{
        cntClamAuth->setVersion_parameter(false);
        cntClamAuth->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 97, 1) && version <= QT_VERSION_CHECK(0, 97, 8)){
        cntClamukoExcludeUID->show();
        cntClamukoExcludeUID->setVersion_parameter(true);
    }else{
        cntClamukoExcludeUID->setVersion_parameter(false);
        cntClamukoExcludeUID->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 96, 0) && version <= QT_VERSION_CHECK(0, 97, 8)){
        cntClamukoScannerCount->show();
        cntClamukoScannerCount->setVersion_parameter(true);
    }else{
        cntClamukoScannerCount->setVersion_parameter(false);
        cntClamukoScannerCount->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 95, 0) && version <= QT_VERSION_CHECK(0, 97, 8)){
        cntClamukoExcludePath->show();
        cntClamukoExcludePath->setVersion_parameter(true);
        cntClamukoIncludePath->show();
        cntClamukoIncludePath->setVersion_parameter(true);
        cntClamukoMaxFileSize->show();
        cntClamukoMaxFileSize->setVersion_parameter(true);
        cntClamukoScanOnAccess->show();
        cntClamukoScanOnAccess->setVersion_parameter(true);
        cntClamukoScanOnClose->show();
        cntClamukoScanOnClose->setVersion_parameter(true);
        cntClamukoScanOnExec->show();
        cntClamukoScanOnExec->setVersion_parameter(true);
        cntClamukoScanOnOpen->show();
        cntClamukoScanOnOpen->setVersion_parameter(true);
    }else{
        cntClamukoExcludePath->setVersion_parameter(false);
        cntClamukoExcludePath->hide();
        cntClamukoIncludePath->setVersion_parameter(false);
        cntClamukoIncludePath->hide();
        cntClamukoMaxFileSize->setVersion_parameter(false);
        cntClamukoMaxFileSize->hide();
        cntClamukoScanOnAccess->setVersion_parameter(false);
        cntClamukoScanOnAccess->hide();
        cntClamukoScanOnClose->setVersion_parameter(false);
        cntClamukoScanOnClose->hide();
        cntClamukoScanOnExec->setVersion_parameter(false);
        cntClamukoScanOnExec->hide();
        cntClamukoScanOnOpen->setVersion_parameter(false);
        cntClamukoScanOnOpen->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 95, 0) && version <= QT_VERSION_CHECK(0, 99, 4)){
        cntAllowSupplementaryGroups->show();
        cntAllowSupplementaryGroups->setVersion_parameter(true);
        cntFreshDetectionStatsCountry->show();
        cntFreshDetectionStatsCountry->setVersion_parameter(true);
        cntFreshSubmitDetectionStats->show();
        cntFreshSubmitDetectionStats->setVersion_parameter(true);
        cntFreshAllowSupplementaryGroups->show();
        cntFreshAllowSupplementaryGroups->setVersion_parameter(true);
    }else{
        cntAllowSupplementaryGroups->setVersion_parameter(false);
        cntAllowSupplementaryGroups->hide();
        cntFreshDetectionStatsCountry->setVersion_parameter(false);
        cntFreshDetectionStatsCountry->hide();
        cntFreshSubmitDetectionStats->setVersion_parameter(false);
        cntFreshSubmitDetectionStats->hide();
        cntFreshAllowSupplementaryGroups->setVersion_parameter(false);
        cntFreshAllowSupplementaryGroups->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 96, 0) && version <= QT_VERSION_CHECK(0, 99, 4)){
        cntFreshDetectionStatsHostID->show();
        cntFreshDetectionStatsHostID->setVersion_parameter(true);
    }else{
        cntFreshDetectionStatsHostID->setVersion_parameter(false);
        cntFreshDetectionStatsHostID->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 95, 0) && version <= QT_VERSION_CHECK(0, 100, 3)){
        cntDetectBrokenExecutables->show();
        cntDetectBrokenExecutables->setVersion_parameter(true);
    }else{
        cntDetectBrokenExecutables->setVersion_parameter(false);
        cntDetectBrokenExecutables->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 95, 0) && version <= QT_VERSION_CHECK(0, 95, 3)){
        cntMailFollowURLs->show();
        cntMailFollowURLs->setVersion_parameter(true);
    }else{
        cntMailFollowURLs->setVersion_parameter(false);
        cntMailFollowURLs->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 98, 3) && version <= QT_VERSION_CHECK(0, 99, 4)){
        cntStatsEnabled->show();
        cntStatsEnabled->setVersion_parameter(true);
        cntStatsHostID->show();
        cntStatsHostID->setVersion_parameter(true);
        cntStatsPEDisabled->show();
        cntStatsPEDisabled->setVersion_parameter(true);
        cntStatsTimeout->show();
        cntStatsTimeout->setVersion_parameter(true);
        cntFreshStatsEnabled->show();
        cntFreshStatsEnabled->setVersion_parameter(true);
        cntFreshStatsHostID->show();
        cntFreshStatsHostID->setVersion_parameter(true);
        cntFreshStatsTimeout->show();
        cntFreshStatsTimeout->setVersion_parameter(true);
    }else{
        cntStatsEnabled->setVersion_parameter(false);
        cntStatsEnabled->hide();
        cntStatsHostID->setVersion_parameter(false);
        cntStatsHostID->hide();
        cntStatsPEDisabled->setVersion_parameter(false);
        cntStatsPEDisabled->hide();
        cntStatsTimeout->setVersion_parameter(false);
        cntStatsTimeout->hide();
        cntFreshStatsEnabled->setVersion_parameter(false);
        cntFreshStatsEnabled->hide();
        cntFreshStatsHostID->setVersion_parameter(false);
        cntFreshStatsHostID->hide();
        cntFreshStatsTimeout->setVersion_parameter(false);
        cntFreshStatsTimeout->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 95, 0) && version <= QT_VERSION_CHECK(0, 100, 3)){
        cntAlgorithmicDetection->show();
        cntAlgorithmicDetection->setVersion_parameter(true);
        cntArchiveBlockEncrypted->show();
        cntArchiveBlockEncrypted->setVersion_parameter(true);
        cntPhishingAlwaysBlockCloak->show();
        cntPhishingAlwaysBlockCloak->setVersion_parameter(true);
        cntPhishingAlwaysBlockSSLMismatch->show();
        cntPhishingAlwaysBlockSSLMismatch->setVersion_parameter(true);
    }else{
        cntAlgorithmicDetection->setVersion_parameter(false);
        cntAlgorithmicDetection->hide();
        cntArchiveBlockEncrypted->setVersion_parameter(false);
        cntArchiveBlockEncrypted->hide();
        cntPhishingAlwaysBlockCloak->setVersion_parameter(false);
        cntPhishingAlwaysBlockCloak->hide();
        cntPhishingAlwaysBlockSSLMismatch->setVersion_parameter(false);
        cntPhishingAlwaysBlockSSLMismatch->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 100, 0)){
        cntBlockMax->show();
        cntBlockMax->setVersion_parameter(true);
    }else{
        cntBlockMax->setVersion_parameter(false);
        cntBlockMax->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 98, 3) && version <= QT_VERSION_CHECK(0, 100, 3)){
        cntPartitionIntersection->show();
        cntPartitionIntersection->setVersion_parameter(true);
    }else{
        cntPartitionIntersection->setVersion_parameter(false);
        cntPartitionIntersection->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 101, 4)){
        cntMaxScanTime->show();
        cntMaxScanTime->setVersion_parameter(true);
    }else{
        cntMaxScanTime->setVersion_parameter(false);
        cntMaxScanTime->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 98, 0) && version <= QT_VERSION_CHECK(0, 101, 5)){
        cntScanOnAccess->show();
        cntScanOnAccess->setVersion_parameter(true);
    }else{
        cntScanOnAccess->setVersion_parameter(false);
        cntScanOnAccess->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 96, 5)){
        cntOLE2BlockMacros->show();
        cntOLE2BlockMacros->setVersion_parameter(true);
    }else{
        cntOLE2BlockMacros->setVersion_parameter(false);
        cntOLE2BlockMacros->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 102, 0)){
        cntOnAccessExcludeUname->show();
        cntOnAccessExcludeUname->setVersion_parameter(true);
        cntOnAccessCurlTimeout->show();
        cntOnAccessCurlTimeout->setVersion_parameter(true);
        cntOnAccessMaxThreads->show();
        cntOnAccessMaxThreads->setVersion_parameter(true);
        cntOnAccessRetryAttempts->show();
        cntOnAccessRetryAttempts->setVersion_parameter(true);
        cntOnAccessDenyOnError->show();
        cntOnAccessDenyOnError->setVersion_parameter(true);
    }else{
        cntOnAccessExcludeUname->setVersion_parameter(false);
        cntOnAccessExcludeUname->hide();
        cntOnAccessCurlTimeout->setVersion_parameter(false);
        cntOnAccessCurlTimeout->hide();
        cntOnAccessMaxThreads->setVersion_parameter(false);
        cntOnAccessMaxThreads->hide();
        cntOnAccessRetryAttempts->setVersion_parameter(false);
        cntOnAccessRetryAttempts->hide();
        cntOnAccessDenyOnError->setVersion_parameter(false);
        cntOnAccessDenyOnError->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 103, 0)){
        cntConcurrentDatabaseReload->show();
        cntConcurrentDatabaseReload->setVersion_parameter(true);
        cntStructuredCCOnly->show();
        cntStructuredCCOnly->setVersion_parameter(true);
    }else{
        cntConcurrentDatabaseReload->setVersion_parameter(false);
        cntConcurrentDatabaseReload->hide();
        cntStructuredCCOnly->setVersion_parameter(false);
        cntStructuredCCOnly->hide();
    }
    if(version >= QT_VERSION_CHECK(0, 103, 3)){
        cntFreshSafeBrowsing->hide();
        cntFreshSafeBrowsing->setVersion_parameter(false);
    }else{
        cntFreshSafeBrowsing->show();
        cntFreshSafeBrowsing->setVersion_parameter(true);
    }
}

void ConfigureDialog::updateClamdconfLoc(QString loc){
    lineEditLocationOfClamdconf->setText(loc);
}

void ConfigureDialog::updateFreshclamconfLoc(QString loc){
    lineEditLocationOfFreshclamconf->setText(loc);
}

void ConfigureDialog::updateEntriesPerPage(QString loc){
    bool ok = false;
    int tmp = loc.toInt(&ok, 10);
    if(ok)
        spinBoxEntriesPerPage->setValue(tmp);
}

void ConfigureDialog::updateMonitorOnAccess(bool state){
    checkBoxMonitorOnAccess->setChecked(state);
}

void ConfigureDialog::updateEnableQuarantine(bool state){
    checkBoxEnableClamOneQuarantine->setChecked(state);
}

void ConfigureDialog::updateEnableSnort(bool state){
    checkBoxEnableClamOneSnort->setChecked(state);
    listWidgetMain->item(3)->setHidden(!state);
}

void ConfigureDialog::updateMaximumQuarantineFileSize(quint64 size){
    spinBoxMaximumFileSizeToQuarantine->setValue(size);
}

void ConfigureDialog::updateLocationQuarantineFileDirectory(QString loc){
    lineEditLocationOfQuarantineFilesDirectory->setText(loc);
}

void ConfigureDialog::updateLocationSnortRules(QString loc){
    cntLocationOfSnortRules->getLineEdit()->setText(loc);
    cntLocationOfSnortRules->getEckbox()->setChecked(!loc.isEmpty());
}

void ConfigureDialog::updateSnortOinkcode(QString code){
    cntSnortOinkcode->getLineEdit()->setText(code);
    cntSnortOinkcode->getEckbox()->setChecked(!code.isEmpty());
}

void ConfigureDialog::updateInstallCond(){
    //TODO
    if(QFileInfo("/etc/xdg/autostart/clamone.desktop").exists()){
        pushButtonAutostartSetup->setText("Uninstall...");
    }else{
        pushButtonAutostartSetup->setText("Install...");
    }
    if( QFileInfo("/lib/systemd/system/clamav-daemon.service").exists() &&
        QFileInfo("/etc/systemd/system/clamav-daemon.service.d").exists() &&
        QFileInfo("/etc/init.d/clamav-daemon").exists()){
        pushButtonAutostartClamavDaemonSetup->setText("Uninstall...");
    }else{
        pushButtonAutostartClamavDaemonSetup->setText("Install...");
    }
    if( QFileInfo("/lib/systemd/system/clamav-freshclam.service").exists() &&
        QFileInfo("/etc/init.d/clamav-freshclam").exists()){
        pushButtonAutostartClamavFreshclamSetup->setText("Uninstall...");
    }else{
        pushButtonAutostartClamavFreshclamSetup->setText("Install...");
    }
    if(QFileInfo("/lib/systemd/system/clamav-onacc.service").exists()){
        pushButtonAutostartClamOnAccSetup->setText("Uninstall...");
    }else{
        pushButtonAutostartClamOnAccSetup->setText("Install...");
    }
    if(QFileInfo("/lib/systemd/system/snort@.service").exists()){
        pushButtonAutostartSnortSetup->setText("Uninstall...");
    }else{
        pushButtonAutostartSnortSetup->setText("Install...");
    }
}

bool ConfigureDialog::fileClamdconfToUI(QString filename)
{
    disableAllClamdconf();
    oldErrClamdconf = QByteArray();
    QFile file(filename);
    if(!file.exists())
        return false;
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;
    while(!file.atEnd()){
        QByteArray line = file.readLine();
        QRegularExpression re;

        re.setPattern("^\\s*#");
        if(line.isEmpty() || re.match(line).hasMatch() ||
                line == QByteArray("\n", 1) || line == QByteArray("\r\n", 2))
            continue;
        if(line.size() > 1 && line.mid(line.size()-2,2) == QByteArray("\r\n", 2))
            line = line.mid(0, line.size()-2);
        if(line.size() > 0 && line.mid(line.size()-1,1) == QByteArray("\n", 1))
            line = line.mid(0, line.size()-1);

        if(cntLocalSocket->lineGrabber(line)) continue;
        if(cntLocalSocketGroup->lineGrabber(line)) continue;
        if(cntLocalSocketMode->lineGrabber(line)) continue;
        if(cntFixStaleSocket->lineGrabber(line)) continue;
        if(cntTCPSocket->lineGrabber(line)) continue;
        if(cntTCPAddr->lineGrabber(line)) continue;
        if(cntMaxConnectionQueueLength->lineGrabber(line)) continue;
        if(cntStreamMaxLength->lineGrabber(line)) continue;
        if(cntStreamMinPort->lineGrabber(line)) continue;
        if(cntStreamMaxPort->lineGrabber(line)) continue;
        if(cntMaxThreads->lineGrabber(line)) continue;
        if(cntReadTimeout->lineGrabber(line)) continue;
        if(cntCommandReadTimeout->lineGrabber(line)) continue;
        if(cntSendBufTimeout->lineGrabber(line)) continue;
        if(cntMaxQueue->lineGrabber(line)) continue;
        if(cntIdleTimeout->lineGrabber(line)) continue;
        if(cntExcludePath->lineGrabber(line)) continue;
        if(cntConcurrentDatabaseReload->lineGrabber(line)) continue;
        if(cntStructuredCCOnly->lineGrabber(line)) continue;
        if(cntLogFile->lineGrabber(line)) continue;
        if(cntLogFileUnlock->lineGrabber(line)) continue;
        if(cntLogFileMaxSize->lineGrabber(line)) continue;
        if(cntLogTime->lineGrabber(line)) continue;
        if(cntLogClean->lineGrabber(line)) continue;
        if(cntLogSyslog->lineGrabber(line)) continue;
        if(cntLogFacility->lineGrabber(line)) continue;
        if(cntLogVerbose->lineGrabber(line)) continue;
        if(cntLogRotate->lineGrabber(line)) continue;
        if(cntExtendedDetectionInfo->lineGrabber(line)) continue;
        if(cntPidFile->lineGrabber(line)) continue;
        if(cntTemporaryDirectory->lineGrabber(line)) continue;
        if(cntDatabaseDirectory->lineGrabber(line)) continue;
        if(cntOfficialDatabaseOnly->lineGrabber(line)) continue;
        if(cntMaxDirectoryRecursion->lineGrabber(line)) continue;
        if(cntFollowDirectorySymlinks->lineGrabber(line)) continue;
        if(cntFollowFileSymlinks->lineGrabber(line)) continue;
        if(cntCrossFilesystems->lineGrabber(line)) continue;
        if(cntSelfCheck->lineGrabber(line)) continue;
        if(cntDisableCache->lineGrabber(line)) continue;
        if(cntVirusEvent->lineGrabber(line)) continue;
        if(cntExitOnOOM->lineGrabber(line)) continue;
        if(cntAllowAllMatchScan->lineGrabber(line)) continue;
        if(cntForeground->lineGrabber(line)) continue;
        if(cntDebug->lineGrabber(line)) continue;
        if(cntLeaveTemporaryFiles->lineGrabber(line)) continue;
        if(cntUser->lineGrabber(line)) continue;
        if(cntBytecode->lineGrabber(line)) continue;
        if(cntBytecodeSecurity->lineGrabber(line)) continue;
        if(cntBytecodeTimeout->lineGrabber(line)) continue;
        if(cntBytecodeUnsigned->lineGrabber(line)) continue;
        if(cntBytecodeMode->lineGrabber(line)) continue;
        if(cntDetectPUA->lineGrabber(line)) continue;
        if(cntExcludePUA->lineGrabber(line)) continue;
        if(cntIncludePUA->lineGrabber(line)) continue;
        if(cntScanPE->lineGrabber(line)) continue;
        if(cntScanELF->lineGrabber(line)) continue;
        if(cntScanMail->lineGrabber(line)) continue;
        if(cntScanPartialMessages->lineGrabber(line)) continue;
        if(cntPhishingSignatures->lineGrabber(line)) continue;
        if(cntPhishingScanURLs->lineGrabber(line)) continue;
        if(cntHeuristicAlerts->lineGrabber(line)) continue;
        if(cntHeuristicScanPrecedence->lineGrabber(line)) continue;
        if(cntStructuredDataDetection->lineGrabber(line)) continue;
        if(cntStructuredMinCreditCardCount->lineGrabber(line)) continue;
        if(cntStructuredMinSSNCount->lineGrabber(line)) continue;
        if(cntStructuredSSNFormatNormal->lineGrabber(line)) continue;
        if(cntStructuredSSNFormatStripped->lineGrabber(line)) continue;
        if(cntScanHTML->lineGrabber(line)) continue;
        if(cntScanOLE2->lineGrabber(line)) continue;
        if(cntScanPDF->lineGrabber(line)) continue;
        if(cntScanSWF->lineGrabber(line)) continue;
        if(cntScanXMLDOCS->lineGrabber(line)) continue;
        if(cntScanHWP3->lineGrabber(line)) continue;
        if(cntScanArchive->lineGrabber(line)) continue;
        if(cntAlertBrokenExecutables->lineGrabber(line)) continue;
        if(cntAlertEncrypted->lineGrabber(line)) continue;
        if(cntAlertEncryptedArchive->lineGrabber(line)) continue;
        if(cntAlertEncryptedDoc->lineGrabber(line)) continue;
        if(cntAlertOLE2Macros->lineGrabber(line)) continue;
        if(cntAlertExceedsMax->lineGrabber(line)) continue;
        if(cntAlertPhishingSSLMismatch->lineGrabber(line)) continue;
        if(cntAlertPhishingCloak->lineGrabber(line)) continue;
        if(cntAlertPartitionIntersection->lineGrabber(line)) continue;
        if(cntForceToDisk->lineGrabber(line)) continue;
        if(cntMaxScanTime->lineGrabber(line)) continue;
        if(cntMaxScanSize->lineGrabber(line)) continue;
        if(cntMaxFileSize->lineGrabber(line)) continue;
        if(cntMaxRecursion->lineGrabber(line)) continue;
        if(cntMaxFiles->lineGrabber(line)) continue;
        if(cntMaxEmbeddedPE->lineGrabber(line)) continue;
        if(cntMaxHTMLNormalize->lineGrabber(line)) continue;
        if(cntMaxHTMLNoTags->lineGrabber(line)) continue;
        if(cntMaxScriptNormalize->lineGrabber(line)) continue;
        if(cntMaxZipTypeRcg->lineGrabber(line)) continue;
        if(cntMaxPartitions->lineGrabber(line)) continue;
        if(cntMaxIconsPE->lineGrabber(line)) continue;
        if(cntMaxRecHWP3->lineGrabber(line)) continue;
        if(cntPCREMatchLimit->lineGrabber(line)) continue;
        if(cntPCRERecMatchLimit->lineGrabber(line)) continue;
        if(cntPCREMaxFileSize->lineGrabber(line)) continue;
        if(cntScanOnAccess->lineGrabber(line)) continue;
        if(cntOnAccessMountPath->lineGrabber(line)) continue;
        if(cntOnAccessIncludePath->lineGrabber(line)) continue;
        if(cntOnAccessExcludePath->lineGrabber(line)) continue;
        if(cntOnAccessExcludeRootUID->lineGrabber(line)) continue;
        if(cntOnAccessExcludeUID->lineGrabber(line)) continue;
        if(cntOnAccessExcludeUname->lineGrabber(line)) continue;
        if(cntOnAccessMaxFileSize->lineGrabber(line)) continue;
        if(cntOnAccessDisableDDD->lineGrabber(line)) continue;
        if(cntOnAccessPrevention->lineGrabber(line)) continue;
        if(cntOnAccessExtraScanning->lineGrabber(line)) continue;
        if(cntOnAccessCurlTimeout->lineGrabber(line)) continue;
        if(cntOnAccessMaxThreads->lineGrabber(line)) continue;
        if(cntOnAccessRetryAttempts->lineGrabber(line)) continue;
        if(cntOnAccessDenyOnError->lineGrabber(line)) continue;
        if(cntDisableCertCheck->lineGrabber(line)) continue;
        if(cntClamAuth->lineGrabber(line)) continue;
        if(cntClamukoExcludePath->lineGrabber(line)) continue;
        if(cntClamukoExcludeUID->lineGrabber(line)) continue;
        if(cntClamukoIncludePath->lineGrabber(line)) continue;
        if(cntClamukoMaxFileSize->lineGrabber(line)) continue;
        if(cntClamukoScannerCount->lineGrabber(line)) continue;
        if(cntClamukoScanOnAccess->lineGrabber(line)) continue;
        if(cntClamukoScanOnClose->lineGrabber(line)) continue;
        if(cntClamukoScanOnExec->lineGrabber(line)) continue;
        if(cntClamukoScanOnOpen->lineGrabber(line)) continue;
        if(cntPreludeEnable->lineGrabber(line)) continue;
        if(cntPreludeAnalyzerName->lineGrabber(line)) continue;
        if(cntAllowSupplementaryGroups->lineGrabber(line)) continue;
        if(cntDetectBrokenExecutables->lineGrabber(line)) continue;
        if(cntMailFollowURLs->lineGrabber(line)) continue;
        if(cntStatsEnabled->lineGrabber(line)) continue;
        if(cntStatsHostID->lineGrabber(line)) continue;
        if(cntStatsPEDisabled->lineGrabber(line)) continue;
        if(cntStatsTimeout->lineGrabber(line)) continue;
        if(cntAlgorithmicDetection->lineGrabber(line)) continue;
        if(cntArchiveBlockEncrypted->lineGrabber(line)) continue;
        if(cntBlockMax->lineGrabber(line)) continue;
        if(cntOLE2BlockMacros->lineGrabber(line)) continue;
        if(cntPartitionIntersection->lineGrabber(line)) continue;
        if(cntPhishingAlwaysBlockCloak->lineGrabber(line)) continue;
        if(cntPhishingAlwaysBlockSSLMismatch->lineGrabber(line)) continue;
    }
    file.close();
    fileUiToClamdconf(&oldClamdconf);
    return true;
}

bool ConfigureDialog::fileFreshclamconfToUI(QString filename)
{
    disableAllFreshclamconf();
    oldFreshclamconf = QByteArray();
    QFile file(filename);
    if(!file.exists())
        return false;
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    while(!file.atEnd()){
        QByteArray line = file.readLine();
        QRegularExpression re;

        re.setPattern("^\\s*#");
        if(line.isEmpty() || re.match(line).hasMatch() ||
                line == QByteArray("\n", 1) || line == QByteArray("\r\n", 2))
            continue;
        if(cntFreshLogFileMaxSize->lineGrabber(line)) continue;
        if(cntFreshLogTime->lineGrabber(line)) continue;
        if(cntFreshLogSyslog->lineGrabber(line)) continue;
        if(cntFreshLogFacility->lineGrabber(line)) continue;
        if(cntFreshLogVerbose->lineGrabber(line)) continue;
        if(cntFreshLogRotate->lineGrabber(line)) continue;
        if(cntFreshPidFile->lineGrabber(line)) continue;
        if(cntFreshDatabaseDirectory->lineGrabber(line)) continue;
        if(cntFreshForeground->lineGrabber(line)) continue;
        if(cntFreshDebug->lineGrabber(line)) continue;
        if(cntFreshUpdateLogFile->lineGrabber(line)) continue;
        if(cntFreshDatabaseOwner->lineGrabber(line)) continue;
        if(cntFreshChecks->lineGrabber(line)) continue;
        if(cntFreshDNSDatabaseInfo->lineGrabber(line)) continue;
        if(cntFreshDatabaseMirror->lineGrabber(line)) continue;
        if(cntFreshPrivateMirror->lineGrabber(line)) continue;
        if(cntFreshMaxAttempts->lineGrabber(line)) continue;
        if(cntFreshScriptedUpdates->lineGrabber(line)) continue;
        if(cntFreshTestDatabases->lineGrabber(line)) continue;
        if(cntFreshCompressLocalDatabase->lineGrabber(line)) continue;
        if(cntFreshExtraDatabase->lineGrabber(line)) continue;
        if(cntFreshExcludeDatabase->lineGrabber(line)) continue;
        if(cntFreshDatabaseCustomURL->lineGrabber(line)) continue;
        if(cntFreshHTTPProxyServer->lineGrabber(line)) continue;
        if(cntFreshHTTPProxyPort->lineGrabber(line)) continue;
        if(cntFreshLogFileMaxSize->lineGrabber(line)) continue;
        if(cntFreshHTTPProxyUsername->lineGrabber(line)) continue;
        if(cntFreshHTTPProxyPassword->lineGrabber(line)) continue;
        if(cntFreshHTTPUserAgent->lineGrabber(line)) continue;
        if(cntFreshNotifyClamd->lineGrabber(line)) continue;
        if(cntFreshOnUpdateExecute->lineGrabber(line)) continue;
        if(cntFreshOnErrorExecute->lineGrabber(line)) continue;
        if(cntFreshOnOutdatedExecute->lineGrabber(line)) continue;
        if(cntFreshLocalIPAddress->lineGrabber(line)) continue;
        if(cntFreshConnectTimeout->lineGrabber(line)) continue;
        if(cntFreshReceiveTimeout->lineGrabber(line)) continue;
        if(cntFreshSafeBrowsing->lineGrabber(line)) continue;
        if(cntFreshBytecode->lineGrabber(line)) continue;
        if(cntFreshAllowSupplementaryGroups->lineGrabber(line)) continue;
        if(cntFreshStatsEnabled->lineGrabber(line)) continue;
        if(cntFreshStatsHostID->lineGrabber(line)) continue;
        if(cntFreshStatsTimeout->lineGrabber(line)) continue;
        if(cntFreshSubmitDetectionStats->lineGrabber(line)) continue;
        if(cntFreshDetectionStatsCountry->lineGrabber(line)) continue;
        if(cntFreshDetectionStatsHostID->lineGrabber(line)) continue;
    }
    file.close();
    fileUiToFreshclamconf(&oldFreshclamconf);
    return true;
}

void ConfigureDialog::fileUiToClamdconf(QByteArray *out){
    LINE_END
    QStringList tmp;
    (*out) = QByteArray("#Automatically Generated by clamav-daemon postinst")+end+
             QByteArray("#To reconfigure clamd run #dpkg-reconfigure clamav-daemon")+end+
             QByteArray("#Please read /usr/share/doc/clamav-daemon/README.Debian.gz for details")+end;

    (*out).append(cntLocalSocket->toConfline());
    (*out).append(cntLocalSocketGroup->toConfline());
    (*out).append(cntLocalSocketMode->toConfline());
    (*out).append(cntFixStaleSocket->toConfline());
    (*out).append(cntTCPSocket->toConfline());
    (*out).append(cntTCPAddr->toConfline());
    (*out).append(cntMaxConnectionQueueLength->toConfline());
    (*out).append(cntStreamMaxLength->toConfline());
    (*out).append(cntStreamMinPort->toConfline());
    (*out).append(cntStreamMaxPort->toConfline());
    (*out).append(cntMaxThreads->toConfline());
    (*out).append(cntReadTimeout->toConfline());
    (*out).append(cntCommandReadTimeout->toConfline());
    (*out).append(cntSendBufTimeout->toConfline());
    (*out).append(cntMaxQueue->toConfline());
    (*out).append(cntIdleTimeout->toConfline());
    (*out).append(cntExcludePath->toConfline());
    (*out).append(cntConcurrentDatabaseReload->toConfline());
    (*out).append(cntStructuredCCOnly->toConfline());
    (*out).append(cntLogFile->toConfline());
    (*out).append(cntLogFileUnlock->toConfline());
    (*out).append(cntLogFileMaxSize->toConfline());
    (*out).append(cntLogTime->toConfline());
    (*out).append(cntLogClean->toConfline());
    (*out).append(cntLogSyslog->toConfline());
    (*out).append(cntLogFacility->toConfline());
    (*out).append(cntLogVerbose->toConfline());
    (*out).append(cntLogRotate->toConfline());
    (*out).append(cntExtendedDetectionInfo->toConfline());
    (*out).append(cntPidFile->toConfline());
    if(cntTemporaryDirectory->getEckbox()->isChecked()){
        (*out).append(cntTemporaryDirectory->toConfline());
    }else{
        (*out).append(QByteArray("# TemporaryDirectory is not set to its default /tmp here to make overriding")+end+
                      QByteArray("# the default with environment variables TMPDIR/TMP/TEMP possible")+end);
    }
    (*out).append(cntDatabaseDirectory->toConfline());
    (*out).append(cntOfficialDatabaseOnly->toConfline());
    (*out).append(cntMaxDirectoryRecursion->toConfline());
    (*out).append(cntFollowDirectorySymlinks->toConfline());
    (*out).append(cntFollowFileSymlinks->toConfline());
    (*out).append(cntCrossFilesystems->toConfline());
    (*out).append(cntSelfCheck->toConfline());
    (*out).append(cntDisableCache->toConfline());
    (*out).append(cntVirusEvent->toConfline());
    (*out).append(cntExitOnOOM->toConfline());
    (*out).append(cntAllowAllMatchScan->toConfline());
    (*out).append(cntForeground->toConfline());
    (*out).append(cntDebug->toConfline());
    (*out).append(cntLeaveTemporaryFiles->toConfline());
    (*out).append(cntUser->toConfline());
    (*out).append(cntBytecode->toConfline());
    (*out).append(cntBytecodeSecurity->toConfline());
    (*out).append(cntBytecodeTimeout->toConfline());
    (*out).append(cntBytecodeUnsigned->toConfline());
    (*out).append(cntBytecodeMode->toConfline());
    (*out).append(cntDetectPUA->toConfline());
    (*out).append(cntExcludePUA->toConfline());
    (*out).append(cntIncludePUA->toConfline());
    (*out).append(cntScanPE->toConfline());
    (*out).append(cntScanELF->toConfline());
    (*out).append(cntScanMail->toConfline());
    (*out).append(cntScanPartialMessages->toConfline());
    (*out).append(cntPhishingSignatures->toConfline());
    (*out).append(cntPhishingScanURLs->toConfline());
    (*out).append(cntHeuristicAlerts->toConfline());
    (*out).append(cntHeuristicScanPrecedence->toConfline());
    (*out).append(cntStructuredDataDetection->toConfline());
    (*out).append(cntStructuredMinCreditCardCount->toConfline());
    (*out).append(cntStructuredMinSSNCount->toConfline());
    (*out).append(cntStructuredSSNFormatNormal->toConfline());
    (*out).append(cntStructuredSSNFormatStripped->toConfline());
    (*out).append(cntScanHTML->toConfline());
    (*out).append(cntScanOLE2->toConfline());
    (*out).append(cntScanPDF->toConfline());
    (*out).append(cntScanSWF->toConfline());
    (*out).append(cntScanXMLDOCS->toConfline());
    (*out).append(cntScanHWP3->toConfline());
    (*out).append(cntScanArchive->toConfline());
    (*out).append(cntAlertBrokenExecutables->toConfline());
    (*out).append(cntAlertEncrypted->toConfline());
    (*out).append(cntAlertEncryptedArchive->toConfline());
    (*out).append(cntAlertEncryptedDoc->toConfline());
    (*out).append(cntAlertOLE2Macros->toConfline());
    (*out).append(cntAlertExceedsMax->toConfline());
    (*out).append(cntAlertPhishingSSLMismatch->toConfline());
    (*out).append(cntAlertPhishingCloak->toConfline());
    (*out).append(cntAlertPartitionIntersection->toConfline());
    (*out).append(cntForceToDisk->toConfline());
    (*out).append(cntMaxScanTime->toConfline());
    (*out).append(cntMaxScanSize->toConfline());
    (*out).append(cntMaxFileSize->toConfline());
    (*out).append(cntMaxRecursion->toConfline());
    (*out).append(cntMaxFiles->toConfline());
    (*out).append(cntMaxEmbeddedPE->toConfline());
    (*out).append(cntMaxHTMLNormalize->toConfline());
    (*out).append(cntMaxHTMLNoTags->toConfline());
    (*out).append(cntMaxScriptNormalize->toConfline());
    (*out).append(cntMaxZipTypeRcg->toConfline());
    (*out).append(cntMaxPartitions->toConfline());
    (*out).append(cntMaxIconsPE->toConfline());
    (*out).append(cntMaxRecHWP3->toConfline());
    (*out).append(cntPCREMatchLimit->toConfline());
    (*out).append(cntPCRERecMatchLimit->toConfline());
    (*out).append(cntPCREMaxFileSize->toConfline());
    (*out).append(cntScanOnAccess->toConfline());
    (*out).append(cntOnAccessMountPath->toConfline());
    (*out).append(cntOnAccessIncludePath->toConfline());
    (*out).append(cntOnAccessExcludePath->toConfline());
    (*out).append(cntOnAccessExcludeRootUID->toConfline());
    (*out).append(cntOnAccessExcludeUID->toConfline());
    (*out).append(cntOnAccessExcludeUname->toConfline());
    (*out).append(cntOnAccessMaxFileSize->toConfline());
    (*out).append(cntOnAccessDisableDDD->toConfline());
    (*out).append(cntOnAccessPrevention->toConfline());
    (*out).append(cntOnAccessExtraScanning->toConfline());
    (*out).append(cntOnAccessCurlTimeout->toConfline());
    (*out).append(cntOnAccessMaxThreads->toConfline());
    (*out).append(cntOnAccessRetryAttempts->toConfline());
    (*out).append(cntOnAccessDenyOnError->toConfline());
    (*out).append(cntDisableCertCheck->toConfline());
    (*out).append(cntClamAuth->toConfline());
    (*out).append(cntClamukoExcludePath->toConfline());
    (*out).append(cntClamukoExcludeUID->toConfline());
    (*out).append(cntClamukoIncludePath->toConfline());
    (*out).append(cntClamukoMaxFileSize->toConfline());
    (*out).append(cntClamukoScannerCount->toConfline());
    (*out).append(cntClamukoScanOnAccess->toConfline());
    (*out).append(cntClamukoScanOnClose->toConfline());
    (*out).append(cntClamukoScanOnExec->toConfline());
    (*out).append(cntClamukoScanOnOpen->toConfline());
    if(cntPreludeEnable->getEckbox()->isChecked()){
        (*out).append(cntPreludeEnable->toConfline());
        if(!cntPreludeAnalyzerName->getLineEdit()->text().isEmpty())
            (*out).append(cntPreludeAnalyzerName->toConfline());
    }
    (*out).append(cntAllowSupplementaryGroups->toConfline());
    (*out).append(cntDetectBrokenExecutables->toConfline());
    (*out).append(cntMailFollowURLs->toConfline());
    (*out).append(cntStatsEnabled->toConfline());
    (*out).append(cntStatsHostID->toConfline());
    (*out).append(cntStatsPEDisabled->toConfline());
    (*out).append(cntStatsTimeout->toConfline());
    (*out).append(cntAlgorithmicDetection->toConfline());
    (*out).append(cntArchiveBlockEncrypted->toConfline());
    (*out).append(cntBlockMax->toConfline());
    (*out).append(cntOLE2BlockMacros->toConfline());
    (*out).append(cntPartitionIntersection->toConfline());
    (*out).append(cntPhishingAlwaysBlockCloak->toConfline());
    (*out).append(cntPhishingAlwaysBlockSSLMismatch->toConfline());
}

void ConfigureDialog::fileUiToFreshclamconf(QByteArray *out)
{
    LINE_END
    (*out) = QByteArray();
    (*out).append(cntFreshLogFileMaxSize->toConfline());
    (*out).append(cntFreshLogTime->toConfline());
    (*out).append(cntFreshLogSyslog->toConfline());
    (*out).append(cntFreshLogFacility->toConfline());
    (*out).append(cntFreshLogVerbose->toConfline());
    (*out).append(cntFreshLogRotate->toConfline());
    (*out).append(cntFreshPidFile->toConfline());
    (*out).append(cntFreshDatabaseDirectory->toConfline());
    (*out).append(cntFreshForeground->toConfline());
    (*out).append(cntFreshDebug->toConfline());
    (*out).append(cntFreshUpdateLogFile->toConfline());
    (*out).append(cntFreshDatabaseOwner->toConfline());
    (*out).append(cntFreshChecks->toConfline());
    (*out).append(cntFreshDNSDatabaseInfo->toConfline());
    (*out).append(cntFreshDatabaseMirror->toConfline());
    (*out).append(cntFreshPrivateMirror->toConfline());
    (*out).append(cntFreshMaxAttempts->toConfline());
    (*out).append(cntFreshScriptedUpdates->toConfline());
    (*out).append(cntFreshTestDatabases->toConfline());
    (*out).append(cntFreshCompressLocalDatabase->toConfline());
    (*out).append(cntFreshExtraDatabase->toConfline());
    (*out).append(cntFreshExcludeDatabase->toConfline());
    (*out).append(cntFreshDatabaseCustomURL->toConfline());
    (*out).append(cntFreshHTTPProxyServer->toConfline());
    (*out).append(cntFreshHTTPProxyPort->toConfline());
    (*out).append(cntFreshHTTPProxyUsername->toConfline());
    (*out).append(cntFreshHTTPProxyPassword->toConfline());
    (*out).append(cntFreshHTTPUserAgent->toConfline());
    (*out).append(cntFreshNotifyClamd->toConfline());
    (*out).append(cntFreshOnUpdateExecute->toConfline());
    (*out).append(cntFreshOnErrorExecute->toConfline());
    (*out).append(cntFreshOnOutdatedExecute->toConfline());
    (*out).append(cntFreshLocalIPAddress->toConfline());
    (*out).append(cntFreshConnectTimeout->toConfline());
    (*out).append(cntFreshReceiveTimeout->toConfline());
    (*out).append(cntFreshSafeBrowsing->toConfline());
    (*out).append(cntFreshBytecode->toConfline());
    (*out).append(cntFreshAllowSupplementaryGroups->toConfline());
    (*out).append(cntFreshDetectionStatsCountry->toConfline());
    (*out).append(cntFreshDetectionStatsHostID->toConfline());
    (*out).append(cntFreshStatsEnabled->toConfline());
    (*out).append(cntFreshStatsHostID->toConfline());
    (*out).append(cntFreshStatsTimeout->toConfline());
    (*out).append(cntFreshSubmitDetectionStats->toConfline());
}

void ConfigureDialog::addExclusionClamdconf(QByteArray exclude_filename){
    listWidgetMain->setCurrentRow(ClamOneConfigStackOrder::ConfigClamdconf);
    tabNetSockScrollArea->verticalScrollBar()->setValue(tabNetSockScrollArea->verticalScrollBar()->maximum());
    cntExcludePath->getEckbox()->setChecked(true);
    QStringList expath = cntExcludePath->getStringListWidget()->getQStringList();
    if(expath.contains(QString(exclude_filename))){
        hide();
        return;
    }
    expath = expath.toSet().toList();
    expath.append(QString(exclude_filename));
    cntExcludePath->getStringListWidget()->setQStringList(expath);
    listen_pushButtonOk_clicked();
}

void ConfigureDialog::options_tab_init(){
    QVBoxLayout *pageOptionsVBox = new QVBoxLayout();
    pageOptions->setLayout(pageOptionsVBox);

    tabWidgetOptions = new QTabWidget();
    pageOptionsVBox->addWidget(tabWidgetOptions);
}

void ConfigureDialog::options_basics_tab_init(){
    tabBasics = new QWidget();
    tabWidgetOptions->addTab(tabBasics, tr("Basics"));

    QVBoxLayout *tabBasicsVBox = new QVBoxLayout();
    tabBasics->setLayout(tabBasicsVBox);

    tabBasicScrollArea = new QScrollArea();
    tabBasicScrollArea->setWidgetResizable(true);
    tabBasicsVBox->addWidget(tabBasicScrollArea);

    tabBasicScrollAreaWidget = new QWidget();
    tabBasicScrollArea->setWidget(tabBasicScrollAreaWidget);

    QVBoxLayout *tabBasicScrollAreaWidgetVBox = new QVBoxLayout();
    tabBasicScrollAreaWidget->setLayout(tabBasicScrollAreaWidgetVBox);

    //LocationOfClamonedb
    horizontalLayoutLocationOfClamonedb = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutLocationOfClamonedb);
    labelLocationOfClamonedb = new QLabel(tr("Location Of clamone.db"));
    labelLocationOfClamonedb->setToolTip(tr("Location on the filesystem where the sqlite database is located containing all Clam One's configurations and entries"));
    horizontalLayoutLocationOfClamonedb->addWidget(labelLocationOfClamonedb);
    horizontalLayoutLocationOfClamonedb->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    lineEditLocationOfClamonedb = new QLineEdit();
    horizontalLayoutLocationOfClamonedb->addWidget(lineEditLocationOfClamonedb);

    //LocationOfClamdconf
    horizontalLayoutLocationOfClamdconf = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutLocationOfClamdconf);
    labelLocationOfClamdconf = new QLabel(tr("Location Of clamd.conf"));
    labelLocationOfClamdconf->setToolTip(tr("Used solely by Clam One, its the location of clamav's clamd.conf file."));
    horizontalLayoutLocationOfClamdconf->addWidget(labelLocationOfClamdconf);
    horizontalLayoutLocationOfClamdconf->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    lineEditLocationOfClamdconf = new QLineEdit();
    horizontalLayoutLocationOfClamdconf->addWidget(lineEditLocationOfClamdconf);
    pushButtonLocationOfClamdconf = new QPushButton();
    pushButtonLocationOfClamdconf->setMaximumWidth(30);
    pushButtonLocationOfClamdconf->setIcon(QIcon(":/images/icon_filedialog.png"));
    pushButtonLocationOfClamdconf->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutLocationOfClamdconf->addWidget(pushButtonLocationOfClamdconf);
    connect(pushButtonLocationOfClamdconf, &QPushButton::clicked, [=](){
        QString tmp = QFileDialog::getOpenFileName(this,
            tr("Select Clamd Configure File"), lineEditLocationOfClamdconf->text(), tr("Config (*.conf);;All (*.*)"));
        if(!tmp.isEmpty())
            lineEditLocationOfClamdconf->setText(tmp);
    });

    //LocationOfFreshclamconf
    horizontalLayoutLocationOfFreshclamconf = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutLocationOfFreshclamconf);
    labelLocationOfFreshclamconf = new QLabel(tr("Location Of freshclam.conf"));
    labelLocationOfFreshclamconf->setToolTip(tr("Used solely by Clam One, its the location of clamav's freshclam.conf file."));
    horizontalLayoutLocationOfFreshclamconf->addWidget(labelLocationOfFreshclamconf);
    horizontalLayoutLocationOfFreshclamconf->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    lineEditLocationOfFreshclamconf = new QLineEdit();
    horizontalLayoutLocationOfFreshclamconf->addWidget(lineEditLocationOfFreshclamconf);
    pushButtonLocationOfFreshclamconf = new QPushButton();
    pushButtonLocationOfFreshclamconf->setMaximumWidth(30);
    pushButtonLocationOfFreshclamconf->setIcon(QIcon(":/images/icon_filedialog.png"));
    pushButtonLocationOfFreshclamconf->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutLocationOfFreshclamconf->addWidget(pushButtonLocationOfFreshclamconf);
    connect(pushButtonLocationOfFreshclamconf, &QPushButton::clicked, [=](){
        QString tmp = QFileDialog::getOpenFileName(this,
            tr("Select Freshclam Configure File"), lineEditLocationOfFreshclamconf->text(), tr("Config (*.conf);;All (*.*)"));
        if(!tmp.isEmpty())
            lineEditLocationOfFreshclamconf->setText(tmp);
    });

    //EntriesPerPage
    horizontalLayoutEntriesPerPage = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutEntriesPerPage);
    labelEntriesPerPage = new QLabel(tr("Entries Per Page"));
    labelEntriesPerPage->setToolTip(tr("Used by Clam One's display, it lists the number of items to display on a single page at one time."));
    horizontalLayoutEntriesPerPage->addWidget(labelEntriesPerPage);
    horizontalLayoutEntriesPerPage->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    spinBoxEntriesPerPage = new QSpinBox();
    spinBoxEntriesPerPage->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
    spinBoxEntriesPerPage->setButtonSymbols(QAbstractSpinBox::NoButtons);
    spinBoxEntriesPerPage->setMinimum(1);
    spinBoxEntriesPerPage->setMaximum(1000000);
    spinBoxEntriesPerPage->setValue(1);
    horizontalLayoutEntriesPerPage->addWidget(spinBoxEntriesPerPage);

    //MonitorOnAccess
    horizontalLayoutMonitorOnAccess = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutMonitorOnAccess);
    labelMonitorOnAccess = new QLabel(tr("Enable ClamOne to monitor OnAccess"));
    labelMonitorOnAccess->setToolTip(tr("Used solely by Clam One, it determines if Clam One is monitoring the state of clamav's OnAccess program."));
    horizontalLayoutMonitorOnAccess->addWidget(labelMonitorOnAccess);
    horizontalLayoutMonitorOnAccess->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    checkBoxMonitorOnAccess = new QCheckBox();
    checkBoxMonitorOnAccess->setText(tr("no"));
    connect(checkBoxMonitorOnAccess, &QCheckBox::stateChanged, [=](int state) {
        (state)?checkBoxMonitorOnAccess->setText(tr("yes")):checkBoxMonitorOnAccess->setText(tr("no"));
    });
    horizontalLayoutMonitorOnAccess->addWidget(checkBoxMonitorOnAccess);

    //EnableClamOneSnort
    horizontalLayoutEnableClamOneSnort = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutEnableClamOneSnort);
    labelEnableClamOneSnort = new QLabel(tr("Enable Clam One for Snort"));
    labelEnableClamOneSnort->setToolTip(tr("Enables Clam One to interact with running snort instance."));
    horizontalLayoutEnableClamOneSnort->addWidget(labelEnableClamOneSnort);
    horizontalLayoutEnableClamOneSnort->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    checkBoxEnableClamOneSnort = new QCheckBox();
    checkBoxEnableClamOneSnort->setText(tr("no"));
    connect(checkBoxEnableClamOneSnort, &QCheckBox::stateChanged, [=](int state) {
        (state)?checkBoxEnableClamOneSnort->setText(tr("yes")):checkBoxEnableClamOneSnort->setText(tr("no"));
        listWidgetMain->item(3)->setHidden(!(bool)state);
    });
    horizontalLayoutEnableClamOneSnort->addWidget(checkBoxEnableClamOneSnort);

    //EnableClamOneQuarantine
    horizontalLayoutEnableClamOneQuarantine = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutEnableClamOneQuarantine);
    labelEnableClamOneQuarantine = new QLabel(tr("Enable Clam One to quarantine files"));
    labelEnableClamOneQuarantine->setToolTip(tr("Enables Clam One to automatically process detected alerts."));
    horizontalLayoutEnableClamOneQuarantine->addWidget(labelEnableClamOneQuarantine);
    horizontalLayoutEnableClamOneQuarantine->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    checkBoxEnableClamOneQuarantine = new QCheckBox();
    checkBoxEnableClamOneQuarantine->setText(tr("no"));
    connect(checkBoxEnableClamOneQuarantine, &QCheckBox::stateChanged, [=](int state) {
        (state)?checkBoxEnableClamOneQuarantine->setText(tr("yes")):checkBoxEnableClamOneQuarantine->setText(tr("no"));
    });
    horizontalLayoutEnableClamOneQuarantine->addWidget(checkBoxEnableClamOneQuarantine);

    //MaximumFileSizeToQuarantine
    horizontalLayoutMaximumFileSizeToQuarantine = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutMaximumFileSizeToQuarantine);
    labelMaximumFileSizeToQuarantine = new QLabel(tr("Maximum filesize to quarantine"));
    labelMaximumFileSizeToQuarantine->setToolTip(tr("Sets the maximum size of a file to try and quarantine."));
    horizontalLayoutMaximumFileSizeToQuarantine->addWidget(labelMaximumFileSizeToQuarantine);
    horizontalLayoutMaximumFileSizeToQuarantine->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    spinBoxMaximumFileSizeToQuarantine = new QSpinBox();
    spinBoxMaximumFileSizeToQuarantine->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
    spinBoxMaximumFileSizeToQuarantine->setButtonSymbols(QAbstractSpinBox::NoButtons);
    spinBoxMaximumFileSizeToQuarantine->setMinimum(0);
    spinBoxMaximumFileSizeToQuarantine->setMaximum(2147483647);
    spinBoxMaximumFileSizeToQuarantine->setValue(25000000);
    horizontalLayoutMaximumFileSizeToQuarantine->addWidget(spinBoxMaximumFileSizeToQuarantine);

    //LocationOfQuarantineFilesDirectory
    horizontalLayoutLocationOfQuarantineFilesDirectory = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutLocationOfQuarantineFilesDirectory);
    labelLocationOfQuarantineFilesDirectory = new QLabel(tr("Location of quarantine files directory"));
    labelLocationOfQuarantineFilesDirectory->setToolTip(tr("Chooses the location for where quarantined files are to reside."));
    horizontalLayoutLocationOfQuarantineFilesDirectory->addWidget(labelLocationOfQuarantineFilesDirectory);
    horizontalLayoutLocationOfQuarantineFilesDirectory->addStretch(); //addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    lineEditLocationOfQuarantineFilesDirectory = new QLineEdit();
    horizontalLayoutLocationOfQuarantineFilesDirectory->addWidget(lineEditLocationOfQuarantineFilesDirectory);
    pushButtonLocationOfQuarantineFilesDirectory = new QPushButton();
    pushButtonLocationOfQuarantineFilesDirectory->setMaximumWidth(30);
    pushButtonLocationOfQuarantineFilesDirectory->setIcon(QIcon(":/images/icon_filedialog.png"));
    pushButtonLocationOfQuarantineFilesDirectory->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutLocationOfQuarantineFilesDirectory->addWidget(pushButtonLocationOfQuarantineFilesDirectory);
    connect(pushButtonLocationOfQuarantineFilesDirectory, &QPushButton::clicked, [=](){
        QString tmp = QFileDialog::getExistingDirectory(this,
            tr("Select Location of Quarantine Files Directory"), lineEditLocationOfQuarantineFilesDirectory->text());
        if(!tmp.isEmpty())
            lineEditLocationOfQuarantineFilesDirectory->setText(tmp);
    });

    horizontalLayoutAutostartSetup = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutAutostartSetup);
    labelAutostartSetup = new QLabel(tr("Autostart ClamOne"));
    labelAutostartSetup->setToolTip(tr("Install startup file (/etc/xdg/autostart/clamone.desktop) for automoatic startup."));
    horizontalLayoutAutostartSetup->addWidget(labelAutostartSetup);
    horizontalLayoutAutostartSetup->addStretch();
    pushButtonAutostartSetup = new QPushButton("Install...");
    pushButtonAutostartSetup->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutAutostartSetup->addWidget(pushButtonAutostartSetup);
    connect(pushButtonAutostartSetup, &QPushButton::clicked, [=](){
        QProcess *p = new QProcess();
        if(pushButtonAutostartSetup->text() == "Install...")
            p->start("pkexec", QStringList({"sh", "-c",
                "cat << EOF > /etc/xdg/autostart/clamone.desktop\n"
                "[Desktop Entry]\n"
                "Encoding=UTF-8\n"
                "Name=ClamOne\n"
                "Comment=ClamOne - clamav frontend.\n"
                "Icon=\n"
                "Exec=/usr/bin/ClamOne\n"
                "Terminal=false\n"
                "Type=Application\n"
                "Categories=\n"
                "X-GNOME-Autostart-Delay=20\n"
                "X-MATE-Autostart-Delay=20\n"
                "Name[C]=clamone\n"
                "EOF\n"
                "chmod 644 /etc/xdg/autostart/clamone.desktop\n"
                "chown root:root /etc/xdg/autostart/clamone.desktop\n"
            }));
        else
            p->start("pkexec", QStringList({"sh", "-c",
                "rm -f /etc/xdg/autostart/clamone.desktop\n"
            }));
        p->waitForFinished();
        updateInstallCond();
        p->close();
    });

    horizontalLayoutAutostartClamavDaemonSetup = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutAutostartClamavDaemonSetup);
    labelAutostartClamavDaemonSetup = new QLabel(tr("Autostart clamav-daemon"));
    labelAutostartClamavDaemonSetup->setToolTip(tr("Install startup file (/lib/systemd/system/clamav-daemon.service) for automoatic clamd startup."));
    horizontalLayoutAutostartClamavDaemonSetup->addWidget(labelAutostartClamavDaemonSetup);
    horizontalLayoutAutostartClamavDaemonSetup->addStretch();
    pushButtonAutostartClamavDaemonSetup = new QPushButton();
    pushButtonAutostartClamavDaemonSetup->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutAutostartClamavDaemonSetup->addWidget(pushButtonAutostartClamavDaemonSetup);
    pushButtonAutostartClamavDaemonSetup->setText("Install...");
    connect(pushButtonAutostartClamavDaemonSetup, &QPushButton::clicked, [=](){
        QProcess *p = new QProcess();
        if(pushButtonAutostartClamavDaemonSetup->text() == "Install...")
            p->start("pkexec", QStringList({"sh", "-c",
                "for proc_id in /proc/[0-9]*; do\n"
                "  if [ -r $proc_id/exe ]; then\n"
                "    if [ -n \"$(readlink -f $proc_id/exe | grep 'clamd$')\" ]; then\n"
                "      proc_name=\"$(readlink -f $proc_id/exe)\"\n"
                "      break;\n"
                "    fi\n"
                "  fi\n"
                "done\n"
                "if [ -z \"$proc_name\" ]; then\n"
                "  for test_name in /usr/local/sbin/clamd /usr/local/bin/clamd /usr/sbin/clamd /usr/bin/clamd; do\n"
                "    if [ -x $test_name ]; then\n"
                "      proc_name=$test_name\n"
                "      break;\n"
                "    fi\n"
                "  done\n"
                "fi\n"
                "if [ -z \"$proc_name\" -o ! -e \"$proc_name\" ]; then\n"
                "  exit 1\n"
                "fi\n"
                "proc_dname=\"$(cat $proc_name | strings | grep 'clamd\\.conf$' | head -n 1)\"\n"
                "cat << EOF > /lib/systemd/system/clamav-daemon.service\n"
                "[Unit]\n"
                "Description=Clam AntiVirus userspace daemon\n"
                "Documentation=man:clamd(8) man:clamd.conf(5) https://www.clamav.net/documents/\n"
                "# Check for database existence\n"
                "ConditionPathExistsGlob=/var/lib/clamav/main.{c[vl]d,inc}\n"
                "ConditionPathExistsGlob=/var/lib/clamav/daily.{c[vl]d,inc}\n"
                "\n"
                "[Service]\n"
                "ExecStart=$proc_name --foreground=true\n"
                "# Reload the database\n"
                "ExecReload=/bin/kill -USR2 \\$MAINPID\n"
                "StandardOutput=syslog\n"
                "TimeoutStartSec=420\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "EOF\n"
                "if [ ! -e /lib/systemd/system/clamav-daemon.service ]; then\n"
                "  exit 1\n"
                "fi\n"
                "chmod 644 /lib/systemd/system/clamav-daemon.service\n"
                "chown root:root /lib/systemd/system/clamav-daemon.service\n"
                "mkdir -p /etc/systemd/system/clamav-daemon.service.d/\n"
                "cat << EOF > /etc/systemd/system/clamav-daemon.service.d/extend.conf\n"
                "[Service]\n"
                "ExecStartPre=-/bin/mkdir -p /run/clamav\n"
                "ExecStartPre=/bin/chown clamav /run/clamav\n"
                "EOF\n"
                "chmod 644 /etc/systemd/system/clamav-daemon.service.d/extend.conf\n"
                "chown root:root /etc/systemd/system/clamav-daemon.service.d/extend.conf\n"
                "cat << \"EOF\" > /etc/init.d/clamav-daemon\n"
                "#! /bin/sh\n"
                "#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.\n"
                "#		Modified for Debian GNU/Linux\n"
                "#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.\n"
                "#               Clamav version by Magnus Ekdahl <magnus@debian.org>\n"
                "#               Heavily reworked by Stephen Gran <sgran@debian.org>\n"
                "#\n"
                "### BEGIN INIT INFO\n"
                "# Provides:          clamav-daemon\n"
                "# Required-Start:    $remote_fs $syslog\n"
                "# Should-Start:      \n"
                "# Required-Stop:     $remote_fs $syslog\n"
                "# Should-Stop:       \n"
                "# Default-Start:     2 3 4 5\n"
                "# Default-Stop:      0 1 6\n"
                "# Short-Description: ClamAV daemon\n"
                "# Description:       Clam AntiVirus userspace daemon\n"
                "### END INIT INFO\n"
                "\n"
                "# The exit status codes should comply with LSB.\n"
                "# https://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html\n"
                "\n"
                "PATH=/sbin:/bin:/usr/sbin:/usr/bin\n"
                "EOF\n"

                "cat << EOF >> /etc/init.d/clamav-daemon\n"
                "DAEMON=$proc_name\n"
                "NAME=\"clamd\"\n"
                "DESC=\"ClamAV daemon\"\n"
                "CLAMAVCONF=$proc_dname\n"
                "EOF\n"

                "cat << \"EOF\" >> /etc/init.d/clamav-daemon\n"
                "SUPERVISOR=/usr/bin/daemon\n"
                "SUPERVISORNAME=daemon\n"
                "SUPERVISORPIDFILE=\"/var/run/clamav/daemon-clamd.pid\"\n"
                "SUPERVISORARGS=\"--name=$NAME --respawn $DAEMON -F $SUPERVISORPIDFILE\"\n"
                "DATABASEDIR=\"/var/lib/clamav\"\n"
                "\n"
                "# required by Debian policy 9.3.2\n"
                "[ -x \"$DAEMON\" ] || exit 0\n"
                "[ -r /etc/default/clamav-daemon ] && . /etc/default/clamav-daemon\n"
                "\n"
                "to_lower()\n"
                "{\n"
                "  word=\"$1\"\n"
                "  lcword=$(echo \"$word\" | tr A-Z a-z)\n"
                "  echo \"$lcword\"\n"
                "}\n"
                "\n"
                "is_true()\n"
                "{\n"
                "  var=\"$1\"\n"
                "  lcvar=$(to_lower \"$var\")\n"
                "  [ 'true' = \"$lcvar\" ] || [ 'yes' = \"$lcvar\" ] || [ 1 = \"$lcvar\" ]\n"
                "  return $?\n"
                "}\n"
                "\n"
                "is_false()\n"
                "{\n"
                "  var=\"$1\"\n"
                "  lcvar=$(to_lower \"$var\")\n"
                "  [ 'false' = \"$lcvar\" ] || [ 'no' = \"$lcvar\" ] || [ 0 = \"$lcvar\" ]\n"
                "  return $?\n"
                "}\n"
                "\n"
                "ucf_cleanup()\n"
                "{\n"
                "  # This only does something if I've fucked up before\n"
                "  # Not entirely impossible :(\n"
                "\n"
                "  configfile=$1\n"
                "\n"
                "  if [ `grep \"$configfile\" /var/lib/ucf/hashfile | wc -l` -gt 1 ]; then\n"
                "    grep -v \"$configfile\" /var/lib/ucf/hashfile > /var/lib/ucf/hashfile.tmp\n"
                "    grep \"$configfile\" /var/lib/ucf/hashfile | tail -n 1  >> /var/lib/ucf/hashfile.tmp\n"
                "    mv /var/lib/ucf/hashfile.tmp /var/lib/ucf/hashfile\n"
                "  fi\n"
                "}\n"
                "\n"
                "add_to_ucf()\n"
                "{\n"
                "  configfile=$1\n"
                "  ucffile=$2\n"
                "\n"
                "  if ! grep -q \"$configfile\" /var/lib/ucf/hashfile; then\n"
                "    md5sum $configfile >> /var/lib/ucf/hashfile\n"
                "    cp $configfile $ucffile\n"
                "  fi\n"
                "}\n"
                "\n"
                "ucf_upgrade_check()\n"
                "{\n"
                "  configfile=$1\n"
                "  sourcefile=$2\n"
                "  ucffile=$3\n"
                "\n"
                "  if [ -f \"$configfile\" ]; then\n"
                "    add_to_ucf $configfile $ucffile\n"
                "    ucf --three-way --debconf-ok \"$sourcefile\" \"$configfile\"\n"
                "  else\n"
                "    [ -d /var/lib/ucf/cache ] || mkdir -p /var/lib/ucf/cache\n"
                "    pathfind restorecon && restorecon /var/lib/ucf/cache\n"
                "    cp $sourcefile $configfile\n"
                "    add_to_ucf $configfile $ucffile\n"
                "  fi\n"
                "}\n"
                "\n"
                "slurp_config()\n"
                "{\n"
                "  CLAMAVCONF=\"$1\"\n"
                "  \n"
                "  if [ -e \"$CLAMAVCONF\" ]; then\n"
                "    for variable in `egrep -a -v '^[[:space:]]*(#|$)' \"$CLAMAVCONF\" | awk '{print $1}'`; do\n"
                "      case \"$variable\" in\n"
                "        DatabaseMirror)\n"
                "        if [ -z \"$DatabaseMirror\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$value $i\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        DatabaseCustomURL)\n"
                "        if [ -z \"$DatabaseCustomURL\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$value $i\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        IncludePUA)\n"
                "        if [ -z \"$IncludePUA\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$i $value\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        ExcludePUA)\n"
                "        if [ -z \"$ExcludePUA\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$i $value\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        ExtraDatabase)\n"
                "        if [ -z \"$ExtraDatabase\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$value $i\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        VirusEvent|OnUpdateExecute|OnErrorExecute|RejectMsg)\n"
                "        value=`grep -a ^$variable $CLAMAVCONF | head -n1 | sed -e s/$variable\\ //`\n"
                "        ;;\n"
                "        *)\n"
                "        value=`grep -a \"^$variable[[:space:]]\" $CLAMAVCONF | head -n1 | awk '{print $2}'`\n"
                "        ;;\n"
                "      esac\n"
                "      if [ -z \"$value\" ]; then \n"
                "        export \"$variable\"=\"true\"\n"
                "      elif [ \"$value\" != \"$variable\" ]; then\n"
                "        export \"$variable\"=\"$value\"\n"
                "      else\n"
                "        export \"$variable\"=\"true\"\n"
                "      fi\n"
                "      unset value\n"
                "    done\n"
                "  fi\n"
                "}\n"
                "\n"
                "pathfind() {\n"
                "  OLDIFS=\"$IFS\"\n"
                "  IFS=:\n"
                "  for p in $PATH; do\n"
                "    if [ -x \"$p/$*\" ]; then\n"
                "      IFS=\"$OLDIFS\"\n"
                "      return 0\n"
                "    fi\n"
                "  done\n"
                "  IFS=\"$OLDIFS\"\n"
                "  return 1\n"
                "}\n"
                "\n"
                "set_debconf_value()\n"
                "{\n"
                "prog=$1\n"
                "name=$2\n"
                "eval variable=\"\\$${name}\"\n"
                "if [ -n \"$variable\" ]; then\n"
                "  db_set clamav-$prog/$name \"$variable\" || true\n"
                "fi\n"
                "}\n"
                "\n"
                "make_dir()\n"
                "{\n"
                "  DIR=$1\n"
                "  if [ -d \"$DIR\" ]; then\n"
                "    return 0;\n"
                "  fi\n"
                "  [ -n \"$User\" ] || User=clamav\n"
                "  mkdir -p -m 0755 \"$DIR\"\n"
                "  chown \"$User\" \"$DIR\"\n"
                "  pathfind restorecon && restorecon \"$DIR\"\n"
                "}\n"
                "\n"
                "# Debconf Functions\n"
                "\n"
                "isdigit ()\n"
                "{\n"
                "  case $1 in\n"
                "    [[:digit:]]*)\n"
                "    ISDIGIT=1\n"
                "    ;;\n"
                "    *)\n"
                "    ISDIGIT=0\n"
                "    ;;\n"
                "  esac\n"
                "}\n"
                "\n"
                "inputdigit ()\n"
                "{\n"
                "  ISDIGIT=0\n"
                "  while [ \"$ISDIGIT\" = '0' ]; do\n"
                "    db_input \"$1\" \"$2\" || true\n"
                "    if ! db_go; then\n"
                "      return 30\n"
                "    fi\n"
                "    db_get $2 || true\n"
                "    isdigit $RET\n"
                "    if [ \"$ISDIGIT\" = '0' ]; then\n"
                "      db_input critical clamav-base/numinfo || true\n"
                "      db_go\n"
                "    fi\n"
                "  done\n"
                "  return 0\n"
                "}\n"
                "\n"
                "StateGeneric()\n"
                "{\n"
                "  PRIO=$1\n"
                "  QUESTION=$2\n"
                "  NEXT=$3\n"
                "  LAST=$4\n"
                "\n"
                "  db_input $PRIO $QUESTION || true\n"
                "  if db_go; then\n"
                "    STATE=$NEXT\n"
                "  else\n"
                "    STATE=$LAST\n"
                "  fi\n"
                "}\n"
                "\n"
                "StateGenericDigit()\n"
                "{\n"
                "  PRIO=$1\n"
                "  QUESTION=$2\n"
                "  NEXT=$3\n"
                "  LAST=$4\n"
                "\n"
                "  inputdigit $PRIO $QUESTION || true\n"
                "  if db_go; then\n"
                "    STATE=$NEXT\n"
                "  else\n"
                "    STATE=$LAST\n"
                "  fi\n"
                "}\n"
                "\n"
                "\n"
                ". /lib/lsb/init-functions\n"
                "\n"
                "if [ ! -f \"$CLAMAVCONF\" ]; then\n"
                "  log_failure_msg \"There is no configuration file for Clamav.\"\n"
                "  log_failure_msg \"Please either dpkg-reconfigure $DESC, or copy the example from\"\n"
                "  log_failure_msg \"/usr/share/doc/clamav-base/examples/ to $CLAMAVCONF and run\"\n"
                "  log_failure_msg \"'invoke-rc.d clamav-daemon start'\"\n"
                "  if [ \"$1\" = \"status\" ]; then\n"
                "    # program or service status is unknown\n"
                "    exit 4;\n"
                "  else\n"
                "    # program is not configured\n"
                "    exit 6;\n"
                "  fi\n"
                "fi\n"
                "\n"
                "slurp_config \"$CLAMAVCONF\"\n"
                "\n"
                "if [ -n \"$Example\" ]; then\n"
                "  log_failure_msg \"Clamav is not configured.\"\n"
                "  log_failure_msg \"Please edit $CLAMAVCONF and run  'invoke-rc.d clamav-daemon start'\"\n"
                "  if [ \"$1\" = \"status\" ]; then\n"
                "    # program or service status is unknown\n"
                "    exit 4;\n"
                "  else\n"
                "    # program is not configured\n"
                "    exit 6;\n"
                "  fi\n"
                "fi\n"
                "\n"
                "if is_true \"$Foreground\"; then\n"
                "  if [ ! -x \"$SUPERVISOR\" ] ; then\n"
                "     log_failure_msg \"Foreground specified, but $SUPERVISORNAME not found\"\n"
                "    if [ \"$1\" = \"status\" ]; then\n"
                "      # program or service status is unknown\n"
                "      exit 4;\n"
                "    else\n"
                "      # program is not configured correctly\n"
                "      exit 6;\n"
                "    fi\n"
                "  else\n"
                "     RUN_SUPERVISED=1\n"
                "  fi\n"
                "fi\n"
                "\n"
                "[ -n \"$User\" ] || User=clamav\n"
                "[ -n \"$DataBaseDirectory\" ] || DataBaseDirectory=/var/run/clamav\n"
                "\n"
                "make_dir \"$DataBaseDirectory\"\n"
                "make_dir $(dirname \"$SUPERVISORPIDFILE\")\n"
                "\n"
                "if [ -z \"$RUN_SUPERVISED\" ]; then\n"
                "	THEPIDFILE=\"$PidFile\"\n"
                "	THEDAEMON=\"$NAME\"\n"
                "	RELOAD=\"1\"\n"
                "else\n"
                "	THEPIDFILE=\"$SUPERVISORPIDFILE\"\n"
                "	THEDAEMON=\"$SUPERVISORNAME\"\n"
                "	RELOAD=\"0\"\n"
                "fi\n"
                "\n"
                "if [ -z \"$THEPIDFILE\" ]\n"
                "then\n"
                "  # Set the default PidFile.\n"
                "  THEPIDFILE='/run/clamav/clamd.pid'\n"
                "fi\n"
                "\n"
                "make_dir $(dirname \"$THEPIDFILE\")\n"
                "chown $User $(dirname \"$THEPIDFILE\")\n"
                "\n"
                "\n"
                "case \"$1\" in\n"
                "  start)\n"
                "  # Check for database existence (start will fail if it's missing)\n"
                "  for db in main daily; do\n"
                "    if [ ! -e \"$DATABASEDIR\"/\"$db\".cvd ] && [ ! -d \"$DATABASEDIR\"/\"$db\".inc ] && [ ! -e \"$DATABASEDIR\"/\"$db\".cld ]; then\n"
                "      log_failure_msg \"Clamav signatures not found in $DATABASEDIR\"\n"
                "      log_failure_msg \"Please retrieve them using freshclam\"\n"
                "      log_failure_msg \"Then run 'invoke-rc.d clamav-daemon start'\"\n"
                "      # this is expected on a fresh installation\n"
                "      exit 0\n"
                "    fi\n"
                "  done\n"
                "  if [ -z \"$RUN_SUPERVISED\" ] ; then\n"
                "    log_daemon_msg \"Starting $DESC\" \"$NAME \"\n"
                "    start-stop-daemon --start --oknodo -c $User --exec $DAEMON --pidfile $THEPIDFILE --quiet -- -c $CLAMAVCONF --pid=$THEPIDFILE\n"
                "    ret=$?\n"
                "  else \n"
                "    log_daemon_msg \"Starting $DESC\" \"$NAME (supervised) \"\n"
                "    $SUPERVISOR $SUPERVISORARGS\n"
                "    ret=$?\n"
                "  fi\n"
                "  log_end_msg $ret\n"
                "  ;;\n"
                "  stop)\n"
                "  log_daemon_msg \"Stopping $DESC\" \"$NAME\"\n"
                "  start-stop-daemon --stop --oknodo --name $THEDAEMON --pidfile $THEPIDFILE --quiet --retry TERM/30/KILL/5\n"
                "  log_end_msg $?\n"
                "  ;;\n"
                "  status)\n"
                "  start-stop-daemon --status --name $THEDAEMON --pidfile $THEPIDFILE\n"
                "  # start-stop-daemon returns LSB compliant exit status codes\n"
                "  ret=$?\n"
                "  if [ \"$ret\" = 0 ]; then\n"
                "      log_success_msg \"$NAME is running\"\n"
                "  else\n"
                "      log_failure_msg \"$NAME is not running\"\n"
                "      exit \"$ret\"\n"
                "  fi\n"
                "  ;;\n"
                "  restart|force-reload)\n"
                "  $0 stop\n"
                "  $0 start\n"
                "  ;;\n"
                "  reload-database)\n"
                "  if [ \"$RELOAD\" = \"1\" ]; then\n"
                "    log_daemon_msg \"Reloading database for $DESC\" \"$NAME\"\n"
                "    pkill -USR2 -F $THEPIDFILE $THEDAEMON 2>/dev/null\n"
                "    log_end_msg $?\n"
                "  else\n"
                "    log_failure_msg \"reload-database does not work in supervised mode.\"\n"
                "    # unimplemented feature\n"
                "    exit 3\n"
                "  fi\n"
                "  ;;\n"
                "  reload-log)\n"
                "  if [ \"$RELOAD\" = \"1\" ]; then\n"
                "    log_daemon_msg \"Reloading log file for $DESC\" \"$NAME\"\n"
                "    pkill -HUP -F $THEPIDFILE $THEDAEMON 2>/dev/null\n"
                "  else\n"
                "    log_failure_msg \"reload-log does not work in supervised mode.\"\n"
                "    # unimplemented feature\n"
                "    exit 3\n"
                "  fi\n"
                "  log_end_msg $?\n"
                "  ;;\n"
                "  *)\n"
                "  log_action_msg \"Usage: $0 {start|stop|restart|force-reload|reload-log|reload-database|status}\" >&2\n"
                "  # invalid arguments\n"
                "  exit 2\n"
                "  ;;\n"
                "esac\n"
                "\n"
                "exit 0\n"


                "EOF\n"

                "systemctl daemon-reload\n"
                "systemctl enable clamav-daemon.service\n"
                "systemctl start clamav-daemon.service\n"
            }));
        else
            p->start("pkexec", QStringList({"sh", "-c",
                "systemctl stop clamav-daemon.service\n"
                "systemctl disable clamav-daemon.service\n"
                "rm -f /lib/systemd/system/clamav-daemon.service\n"
                "rm -rf /etc/systemd/system/clamav-daemon.service.d\n"
                "rm -f /etc/init.d/clamav-daemon\n"
                "systemctl daemon-reload\n"
            }));
        p->waitForFinished();
        updateInstallCond();
        p->close();
    });

    horizontalLayoutAutostartClamavFreshclamSetup = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutAutostartClamavFreshclamSetup);
    labelAutostartClamavFreshclamSetup = new QLabel(tr("Autostart clamav-freshclam"));
    labelAutostartClamavFreshclamSetup->setToolTip(tr("Install startup file (/lib/systemd/system/clamav-freshclam.service) for automoatic freshclam startup."));
    horizontalLayoutAutostartClamavFreshclamSetup->addWidget(labelAutostartClamavFreshclamSetup);
    horizontalLayoutAutostartClamavFreshclamSetup->addStretch();
    pushButtonAutostartClamavFreshclamSetup = new QPushButton();
    pushButtonAutostartClamavFreshclamSetup->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutAutostartClamavFreshclamSetup->addWidget(pushButtonAutostartClamavFreshclamSetup);
    pushButtonAutostartClamavFreshclamSetup->setText("Install...");
    connect(pushButtonAutostartClamavFreshclamSetup, &QPushButton::clicked, [=](){
        QProcess *p = new QProcess();
        //strings "$(strings $proc_name | grep '^/.' | tail -n 1)"/libfreshclam.so* | grep 'freshclam\.conf$' | uniq | head -n 1
        if(pushButtonAutostartClamavFreshclamSetup->text() == "Install...")
            p->start("pkexec", QStringList({"sh", "-c",
                "for proc_id in /proc/[0-9]*; do\n"
                "  if [ -r $proc_id/exe ]; then\n"
                "    if [ -n \"$(readlink -f $proc_id/exe | grep 'freshclam$')\" ]; then\n"
                "      proc_name=\"$(readlink -f $proc_id/exe)\"\n"
                "      break;\n"
                "    fi\n"
                "  fi\n"
                "done\n"
                "if [ -z \"$proc_name\" ]; then\n"
                "  for test_name in /usr/local/sbin/freshclam /usr/local/bin/freshclam /usr/sbin/freshclam /usr/bin/freshclam; do\n"
                "    if [ -x $test_name ]; then\n"
                "      proc_name=$test_name\n"
                "      break;\n"
                "    fi\n"
                "  done\n"
                "fi\n"
                "if [ -z \"$proc_name\" -o ! -e \"$proc_name\" ]; then\n"
                "  exit 1\n"
                "fi\n"
                "proc_cname=\"$(cat $proc_name | strings | grep 'clamd\\.conf$' | head -n 1)\"\n"
                "proc_fname=\"$(cat $proc_name | strings | grep 'freshclam\\.conf$' | head -n 1)\"\n"

                "cat << EOF > /lib/systemd/system/clamav-freshclam.service\n"
                "[Unit]\n"
                "Description=ClamAV virus database updater\n"
                "Documentation=man:freshclam(1) man:freshclam.conf(5) https://www.clamav.net/documents\n"
                "# If user wants it run from cron, don't start the daemon.\n"
                "ConditionPathExists=!/etc/cron.d/clamav-freshclam\n"
                "Wants=network-online.target\n"
                "After=network-online.target\n"
                "\n"
                "[Service]\n"
                "ExecStart=$proc_name -d --foreground=true\n"
                "StandardOutput=syslog\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "EOF\n"
                "if [ ! -e /lib/systemd/system/clamav-freshclam.service ]; then\n"
                "  exit 1\n"
                "fi\n"
                "chmod 644 /lib/systemd/system/clamav-freshclam.service\n"
                "chown root:root /lib/systemd/system/clamav-freshclam.service\n"

                "cat << \"EOF\" > /etc/init.d/clamav-freshclam\n"
                "#!/bin/sh\n"
                "\n"
                "### BEGIN INIT INFO\n"
                "# Provides:          clamav-freshclam\n"
                "# Required-Start:    $remote_fs $syslog\n"
                "# Should-Start:      clamav-daemon\n"
                "# Required-Stop:     $remote_fs $syslog\n"
                "# Should-Stop:       \n"
                "# Default-Start:     2 3 4 5\n"
                "# Default-Stop:      0 1 6\n"
                "# Short-Description: ClamAV virus database updater\n"
                "# Description:       Clam AntiVirus virus database updater\n"
                "### END INIT INFO\n"
                "\n"
                "# The exit status codes should comply with LSB.\n"
                "# https://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html\n"
                "\n"
                "EOF\n"

                "cat << EOF >> /etc/init.d/clamav-freshclam\n"
                "DAEMON=$proc_name\n"
                "NAME=freshclam\n"
                "DESC=\"ClamAV virus database updater\"\n"
                "\n"
                "# required by Debian policy 9.3.2\n"
                "[ -x \\$DAEMON ] || exit 0\n"
                "\n"
                "CLAMAV_CONF_FILE=$proc_cname\n"
                "FRESHCLAM_CONF_FILE=$proc_fname\n"
                "\n"
                "EOF\n"

                "cat << \"EOF\" >> /etc/init.d/clamav-freshclam\n"
                "to_lower()\n"
                "{\n"
                "  word=\"$1\"\n"
                "  lcword=$(echo \"$word\" | tr A-Z a-z)\n"
                "  echo \"$lcword\"\n"
                "}\n"
                "\n"
                "is_true()\n"
                "{\n"
                "  var=\"$1\"\n"
                "  lcvar=$(to_lower \"$var\")\n"
                "  [ 'true' = \"$lcvar\" ] || [ 'yes' = \"$lcvar\" ] || [ 1 = \"$lcvar\" ]\n"
                "  return $?\n"
                "}\n"
                "\n"
                "is_false()\n"
                "{\n"
                "  var=\"$1\"\n"
                "  lcvar=$(to_lower \"$var\")\n"
                "  [ 'false' = \"$lcvar\" ] || [ 'no' = \"$lcvar\" ] || [ 0 = \"$lcvar\" ]\n"
                "  return $?\n"
                "}\n"
                "\n"
                "ucf_cleanup()\n"
                "{\n"
                "  # This only does something if I've fucked up before\n"
                "  # Not entirely impossible :(\n"
                "\n"
                "  configfile=$1\n"
                "\n"
                "  if [ `grep \"$configfile\" /var/lib/ucf/hashfile | wc -l` -gt 1 ]; then\n"
                "    grep -v \"$configfile\" /var/lib/ucf/hashfile > /var/lib/ucf/hashfile.tmp\n"
                "    grep \"$configfile\" /var/lib/ucf/hashfile | tail -n 1  >> /var/lib/ucf/hashfile.tmp\n"
                "    mv /var/lib/ucf/hashfile.tmp /var/lib/ucf/hashfile\n"
                "  fi\n"
                "}\n"
                "\n"
                "add_to_ucf()\n"
                "{\n"
                "  configfile=$1\n"
                "  ucffile=$2\n"
                "\n"
                "  if ! grep -q \"$configfile\" /var/lib/ucf/hashfile; then\n"
                "    md5sum $configfile >> /var/lib/ucf/hashfile\n"
                "    cp $configfile $ucffile\n"
                "  fi\n"
                "}\n"
                "\n"
                "ucf_upgrade_check()\n"
                "{\n"
                "  configfile=$1\n"
                "  sourcefile=$2\n"
                "  ucffile=$3\n"
                "\n"
                "  if [ -f \"$configfile\" ]; then\n"
                "    add_to_ucf $configfile $ucffile\n"
                "    ucf --three-way --debconf-ok \"$sourcefile\" \"$configfile\"\n"
                "  else\n"
                "    [ -d /var/lib/ucf/cache ] || mkdir -p /var/lib/ucf/cache\n"
                "    pathfind restorecon && restorecon /var/lib/ucf/cache\n"
                "    cp $sourcefile $configfile\n"
                "    add_to_ucf $configfile $ucffile\n"
                "  fi\n"
                "}\n"
                "\n"
                "slurp_config()\n"
                "{\n"
                "  CLAMAVCONF=\"$1\"\n"
                "  \n"
                "  if [ -e \"$CLAMAVCONF\" ]; then\n"
                "    for variable in `egrep -a -v '^[[:space:]]*(#|$)' \"$CLAMAVCONF\" | awk '{print $1}'`; do\n"
                "      case \"$variable\" in\n"
                "        DatabaseMirror)\n"
                "        if [ -z \"$DatabaseMirror\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$value $i\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        DatabaseCustomURL)\n"
                "        if [ -z \"$DatabaseCustomURL\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$value $i\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        IncludePUA)\n"
                "        if [ -z \"$IncludePUA\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$i $value\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        ExcludePUA)\n"
                "        if [ -z \"$ExcludePUA\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$i $value\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        ExtraDatabase)\n"
                "        if [ -z \"$ExtraDatabase\" ]; then\n"
                "          for i in `grep -a ^$variable $CLAMAVCONF | awk '{print $2}'`; do\n"
                "            value=\"$value $i\"\n"
                "          done\n"
                "        else\n"
                "          continue\n"
                "        fi\n"
                "        ;;\n"
                "        VirusEvent|OnUpdateExecute|OnErrorExecute|RejectMsg)\n"
                "        value=`grep -a ^$variable $CLAMAVCONF | head -n1 | sed -e s/$variable\\ //`\n"
                "        ;;\n"
                "        *)\n"
                "        value=`grep -a \"^$variable[[:space:]]\" $CLAMAVCONF | head -n1 | awk '{print $2}'`\n"
                "        ;;\n"
                "      esac\n"
                "      if [ -z \"$value\" ]; then \n"
                "        export \"$variable\"=\"true\"\n"
                "      elif [ \"$value\" != \"$variable\" ]; then\n"
                "        export \"$variable\"=\"$value\"\n"
                "      else\n"
                "        export \"$variable\"=\"true\"\n"
                "      fi\n"
                "      unset value\n"
                "    done\n"
                "  fi\n"
                "}\n"
                "\n"
                "pathfind() {\n"
                "  OLDIFS=\"$IFS\"\n"
                "  IFS=:\n"
                "  for p in $PATH; do\n"
                "    if [ -x \"$p/$*\" ]; then\n"
                "      IFS=\"$OLDIFS\"\n"
                "      return 0\n"
                "    fi\n"
                "  done\n"
                "  IFS=\"$OLDIFS\"\n"
                "  return 1\n"
                "}\n"
                "\n"
                "set_debconf_value()\n"
                "{\n"
                "prog=$1\n"
                "name=$2\n"
                "eval variable=\"\\$${name}\"\n"
                "if [ -n \"$variable\" ]; then\n"
                "  db_set clamav-$prog/$name \"$variable\" || true\n"
                "fi\n"
                "}\n"
                "\n"
                "make_dir()\n"
                "{\n"
                "  DIR=$1\n"
                "  if [ -d \"$DIR\" ]; then\n"
                "    return 0;\n"
                "  fi\n"
                "  [ -n \"$User\" ] || User=clamav\n"
                "  mkdir -p -m 0755 \"$DIR\"\n"
                "  chown \"$User\" \"$DIR\"\n"
                "  pathfind restorecon && restorecon \"$DIR\"\n"
                "}\n"
                "\n"
                "# Debconf Functions\n"
                "\n"
                "isdigit ()\n"
                "{\n"
                "  case $1 in\n"
                "    [[:digit:]]*)\n"
                "    ISDIGIT=1\n"
                "    ;;\n"
                "    *)\n"
                "    ISDIGIT=0\n"
                "    ;;\n"
                "  esac\n"
                "}\n"
                "\n"
                "inputdigit ()\n"
                "{\n"
                "  ISDIGIT=0\n"
                "  while [ \"$ISDIGIT\" = '0' ]; do\n"
                "    db_input \"$1\" \"$2\" || true\n"
                "    if ! db_go; then\n"
                "      return 30\n"
                "    fi\n"
                "    db_get $2 || true\n"
                "    isdigit $RET\n"
                "    if [ \"$ISDIGIT\" = '0' ]; then\n"
                "      db_input critical clamav-base/numinfo || true\n"
                "      db_go\n"
                "    fi\n"
                "  done\n"
                "  return 0\n"
                "}\n"
                "\n"
                "StateGeneric()\n"
                "{\n"
                "  PRIO=$1\n"
                "  QUESTION=$2\n"
                "  NEXT=$3\n"
                "  LAST=$4\n"
                "\n"
                "  db_input $PRIO $QUESTION || true\n"
                "  if db_go; then\n"
                "    STATE=$NEXT\n"
                "  else\n"
                "    STATE=$LAST\n"
                "  fi\n"
                "}\n"
                "\n"
                "StateGenericDigit()\n"
                "{\n"
                "  PRIO=$1\n"
                "  QUESTION=$2\n"
                "  NEXT=$3\n"
                "  LAST=$4\n"
                "\n"
                "  inputdigit $PRIO $QUESTION || true\n"
                "  if db_go; then\n"
                "    STATE=$NEXT\n"
                "  else\n"
                "    STATE=$LAST\n"
                "  fi\n"
                "}\n"
                "\n"
                "\n"
                ". /lib/lsb/init-functions\n"
                "\n"
                "slurp_config \"$FRESHCLAM_CONF_FILE\"\n"
                "\n"
                "if [ -z \"$PidFile\" ]\n"
                "then\n"
                "  # Set the default PidFile.\n"
                "  PidFile='/run/clamav/freshclam.pid'\n"
                "fi\n"
                "[ -n \"$DataBaseDirectory\" ] || DataBaseDirectory=/var/run/clamav\n"
                "\n"
                "make_dir \"$DataBaseDirectory\"\n"
                "make_dir $(dirname \"$PidFile\")\n"
                "\n"
                "[ -z \"$UpdateLogFile\" ] && UpdateLogFile=/var/log/clamav/freshclam.log\n"
                "[ -z \"$DatabaseDirectory\" ] && DatabaseDirectory=/var/lib/clamav/\n"
                "[ -n \"$DatabaseOwner\" ] || DatabaseOwner=clamav\n"
                "\n"
                "case \"$1\" in\n"
                "  no-daemon)\n"
                "  su \"$DatabaseOwner\" -p -s /bin/sh -c \"freshclam -l $UpdateLogFile --datadir $DatabaseDirectory\"\n"
                "  ;;\n"
                "  start)\n"
                "  if [ ! -f \"$PidFile\" ]; then\n"
                "    # If clamd is run under a different UID than freshclam then we need\n"
                "    # to make sure the PidFile can be written or else we won't be able to\n"
                "    # kill it.\n"
                "    touch $PidFile\n"
                "    chown $DatabaseOwner $PidFile\n"
                "  fi\n"
                "  # If user wants it run from cron, we only accept no-daemon and stop\n"
                "  if [ -f /etc/cron.d/clamav-freshclam ]; then\n"
                "    log_warning_msg \"Not starting $NAME - cron option selected\"\n"
                "    log_warning_msg \"Run the init script with the 'no-daemon' option\"\n"
                "    # this is similar to the daemon already running\n"
                "    exit 0\n"
                "  fi\n"
                "  log_daemon_msg \"Starting $DESC\" \"$NAME\"\n"
                "  start-stop-daemon --start --oknodo -c \"$DatabaseOwner\" --exec $DAEMON --pidfile $PidFile --quiet -- -d --quiet --config-file=$FRESHCLAM_CONF_FILE --pid=$PidFile\n"
                "  log_end_msg $?\n"
                "  ;;\n"
                "  stop)\n"
                "  log_daemon_msg \"Stopping $DESC\" \"$NAME\"\n"
                "  start-stop-daemon --stop --oknodo --name $NAME --pidfile $PidFile --quiet --retry TERM/30/KILL/5\n"
                "  log_end_msg $?\n"
                "  ;;\n"
                "  restart|force-reload)\n"
                "  $0 stop\n"
                "  $0 start\n"
                "  ;;\n"
                "  reload-log)\n"
                "  # If user wants it run from cron, we only accept no-daemon and stop\n"
                "  if [ -f /etc/cron.d/clamav-freshclam ]; then\n"
                "    log_warning_msg \"Not reloading log for $NAME - cron option selected\"\n"
                "    # log-reloading is not needed, because freshclam is not run as daemon\n"
                "    exit 0\n"
                "  fi\n"
                "  log_daemon_msg \"Reloading $DESC\" \"$NAME\"\n"
                "  pkill -HUP -F $PidFile $NAME\n"
                "  log_end_msg $?\n"
                "  ;;\n"
                "  skip)\n"
                "  ;;\n"
                "  status)\n"
                "  start-stop-daemon --status --name $NAME --pidfile $PidFile\n"
                "  ret=\"$?\"\n"
                "   if [ \"$ret\" = 0 ]; then\n"
                "     log_success_msg \"$NAME is running\"\n"
                "     exit 0\n"
                "   else\n"
                "     log_failure_msg \"$NAME is not running\"\n"
                "     exit \"$ret\"\n"
                "  fi\n"
                "  ;;\n"
                "  *)\n"
                "  log_action_msg \"Usage: $0 {no-daemon|start|stop|restart|force-reload|reload-log|skip|status}\" >&2\n"
                "  # invalid arguments\n"
                "  exit 2\n"
                "  ;;\n"
                "esac\n"
                "\n"
                "exit 0\n"
                "EOF\n"

                "systemctl daemon-reload\n"
                "systemctl enable clamav-freshclam.service\n"
                "systemctl start clamav-freshclam.service\n"
            }));
        else
            p->start("pkexec", QStringList({"sh", "-c",
                "systemctl stop clamav-freshclam.service\n"
                "systemctl disable clamav-freshclam.service\n"
                "rm -f /lib/systemd/system/clamav-freshclam.service\n"
                "rm -rf /etc/systemd/system/clamav-freshclam.service.d\n"
                "rm -f /etc/init.d/clamav-freshclam\n"
                "systemctl daemon-reload\n"
            }));
        p->waitForFinished();
        updateInstallCond();
        p->close();
    });

    horizontalLayoutAutostartClamOnAccSetup = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutAutostartClamOnAccSetup);
    labelAutostartClamOnAccSetup = new QLabel(tr("Autostart ClamOnAccess"));
    labelAutostartClamOnAccSetup->setToolTip(tr("Install systemd startup file (/lib/systemd/system/clamav-onacc.service) for automoatic startup<br /> of ClamOnAccess."));
    horizontalLayoutAutostartClamOnAccSetup->addWidget(labelAutostartClamOnAccSetup);
    horizontalLayoutAutostartClamOnAccSetup->addStretch();
    pushButtonAutostartClamOnAccSetup = new QPushButton("Install...");
    pushButtonAutostartClamOnAccSetup->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutAutostartClamOnAccSetup->addWidget(pushButtonAutostartClamOnAccSetup);
    connect(pushButtonAutostartClamOnAccSetup, &QPushButton::clicked, [=](){
        if(
            (!cntOnAccessExcludeUname->getEckbox()->isChecked() || !cntOnAccessExcludeUname->getStringListWidget()->getQStringList().length())
            &&
            (!cntOnAccessExcludeUID->getEckbox()->isChecked() || !cntOnAccessExcludeUID->getListSpinBoxWidget()->getQListInt().length())
            ){
            QMessageBox::warning(this, tr("OnAccessExcludeUname or OnAccessExcludeUID Required"), tr("The field \"OnAccessExcludeUname\" or the field \"OnAccessExcludeUID\" needs to be enabled and have have entries in order for OnAccess to run. If you are unsure, try setting the OnAccessExcludeUname to have the username you placed in (Scanning >> User) in the configureation. Aborting autostart initialization..."));
            return;
        }
        if(!cntOnAccessIncludePath->getEckbox()->isChecked() || !cntOnAccessIncludePath->getStringListWidget()->getQStringList().length() ){
            QMessageBox::warning(this, tr("OnAccessIncludePath Required"), tr("The field \"OnAccessIncludePath\" needs to be enabled and have have entries in order for OnAccess to run. Aborting autostart initialization..."));
            return;
        }
        QProcess *p = new QProcess();
        if(pushButtonAutostartClamOnAccSetup->text() == "Install...")
            p->start("pkexec", QStringList({"sh", "-c",
                "cat << EOF > /lib/systemd/system/clamav-onacc.service\n"
                "[Unit]\n"
                "Description=ClamAV On Access Scanner\n"
                "Requires=clamav-daemon.service\n"
                "After=clamav-daemon.service syslog.target network.target\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "User=root\n"
                "ExecStart=/usr/sbin/clamonacc -F\n"
                "Restart=on-failure\n"
                "RestartSec=120s\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "EOF\n"
                "chmod 644 /lib/systemd/system/clamav-onacc.service\n"
                "chown root:root /lib/systemd/system/clamav-onacc.service\n"
                "systemctl daemon-reload\n"
                "systemctl enable clamav-onacc.service\n"
                "systemctl start clamav-onacc.service\n"
            }));
        else
            p->start("pkexec", QStringList({"sh", "-c",
                "systemctl stop clamav-onacc.service\n"
                "systemctl disable clamav-onacc.service\n"
                "rm -f /lib/systemd/system/clamav-onacc.service\n"
                "systemctl daemon-reload\n"
            }));
        p->waitForFinished();
        updateInstallCond();
        p->close();
    });

    horizontalLayoutAutostartSnortSetup = new QHBoxLayout();
    tabBasicScrollAreaWidgetVBox->addLayout(horizontalLayoutAutostartSnortSetup);
    labelAutostartSnortSetup = new QLabel(tr("Autostart Snort"));
    labelAutostartSnortSetup->setToolTip(tr("Install systemd startup file (/lib/systemd/system/snort@.service) for automoatic startup of Snort.<br />Then add each network interface to the start file (i.e. snort@eth0, snort@eth1, snort@wlan0, etc)"));
    horizontalLayoutAutostartSnortSetup->addWidget(labelAutostartSnortSetup);
    horizontalLayoutAutostartSnortSetup->addStretch();
    pushButtonAutostartSnortSetup = new QPushButton("Install...");
    pushButtonAutostartSnortSetup->setFocusPolicy(Qt::NoFocus);
    horizontalLayoutAutostartSnortSetup->addWidget(pushButtonAutostartSnortSetup);
    connect(pushButtonAutostartSnortSetup, &QPushButton::clicked, [=](){
        QProcess *p = new QProcess();
        if(pushButtonAutostartSnortSetup->text() == "Install...")
            p->start("pkexec", QStringList({"sh", "-c",
                "cat << EOF > /usr/bin/snort\n"
                "#!/bin/sh\n"
                "if [ -n \"\\$1\" ]; then\n"
                "  NETRANGE=\"\\$(ip address show \"\\$1\" 2>&1 | grep \"inet \" | awk '{print \\$2}')\"\n"
                "  while [ -z \"\\$NETRANGE\" ]; do\n"
                "    sleep 20;\n"
                "    NETRANGE=\"\\$(ip address show \"\\$1\" 2>&1 | grep \"inet \" | awk '{print \\$2}')\"\n"
                "  done\n"
                "  /usr/local/bin/snort -m 027 -d -l /var/log/snort -u snort -g snort -c /etc/snort/etc/snort.conf -S HOME_NET=[\\$NETRANGE] -i \"\\$1\"\n"
                "fi\n"
                "EOF\n"
                "chown root:root /usr/bin/snort\n"
                "chmod 755 /usr/bin/snort\n"
                "cat << EOF > /lib/systemd/system/snort\\@.service\n"
                "[Unit]\n"
                "Description=Snort Network Intrusion Detection System connection to %i\n"
                "Documentation=man:snort(8) man:snort.conf(5) https://snort.org/documents/\n"
                "# Check for log directory existence\n"
                "ConditionPathExists=/var/log/snort\n"
                "\n"
                "[Service]\n"
                "ExecStart=/usr/bin/snort %i\n"
                "# Reload the ruleset\n"
                "ExecReload=/bin/kill -HUP \\$MAINPID\n"
                "StandardOutput=syslog\n"
                "Restart=on-failure\n"
                "TimeoutStartSec=350\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "EOF\n"
                "chmod 644 /lib/systemd/system/snort\\@.service\n"
                "chown root:root /lib/systemd/system/snort\\@.service\n"
                "systemctl daemon-reload\n"
                "for iface in $(ip address show | grep '^[^ ]' | awk '{print $2}' | tr -d ':' | tail -n +2); do\n"
                "  if [ \"$(systemctl is-enabled snort@$iface)\" != \"enabled\" ]; then\n"
                "    systemctl enable snort@$iface\n"
                "  fi\n"
                "  if [ \"$(systemctl is-active snort@$iface)\" != \"active\" ]; then\n"
                "    systemctl start snort@$iface\n"
                "  fi\n"
                "done\n"
            }));
        else
            p->start("pkexec", QStringList({"sh", "-c",
                "for iface in $(ip address show | grep '^[^ ]' | awk '{print $2}' | tr -d ':' | tail -n +2); do\n"
                "  if [ \"$(systemctl is-active snort@$iface)\" = \"active\" ]; then\n"
                "    systemctl stop snort@$iface\n"
                "  fi\n"
                "  if [ \"$(systemctl is-enabled snort@$iface)\" = \"enabled\" ]; then\n"
                "    systemctl disable snort@$iface\n"
                "  fi\n"
                "done\n"
                "rm -f /lib/systemd/system/snort\\@.service\n"
                "systemctl daemon-reload\n"
            }));
        p->waitForFinished();
        updateInstallCond();
        p->close();
    });

    tabBasicScrollAreaWidgetVBox->addStretch();
}

void ConfigureDialog::clamd_tab_init(){
    QVBoxLayout *pageClamdVBox = new QVBoxLayout();
    pageClamd->setLayout(pageClamdVBox);

    tabWidgetClamd = new QTabWidget();
    pageClamdVBox->addWidget(tabWidgetClamd);
}

void ConfigureDialog::clamd_netsock_tab_init(){
    tabNetSock = new QWidget();
    tabWidgetClamd->addTab(tabNetSock, tr("NetSock"));

    QVBoxLayout *tabNetSockVBox = new QVBoxLayout();
    tabNetSock->setLayout(tabNetSockVBox);

    tabNetSockScrollArea = new QScrollArea();
    tabNetSockScrollArea->setWidgetResizable(true);
    tabNetSockVBox->addWidget(tabNetSockScrollArea);

    tabNetSockScrollAreaWidget = new QWidget();
    tabNetSockScrollArea->setWidget(tabNetSockScrollAreaWidget);

    QVBoxLayout *tabNetSockScrollAreaWidgetVBox = new QVBoxLayout();
    tabNetSockScrollAreaWidget->setLayout(tabNetSockScrollAreaWidgetVBox);

    ////

    //LocalSocket
    cntLocalSocket = new LineEditPlug("LocalSocket",
                        tr("STRING<br />"
                        "Path to a local (Unix) socket the daemon will listen on.<br />"
                        "Default: disabled"), "/tmp/clamd.socket");
    tabNetSockScrollAreaWidgetVBox->addWidget(cntLocalSocket);

    //LocalSocketGroup
    cntLocalSocketGroup = new LineEditPlug("LocalSocketGroup",
                        tr("STRING<br />"
                        "Sets the group ownership on the unix socket.<br />"
                        "Default: the primary group of the user running clamd"), "virusgroup");
    tabNetSockScrollAreaWidgetVBox->addWidget(cntLocalSocketGroup);

    //LocalSocketMode
    cntLocalSocketMode = new LineEditPlug("LocalSocketMode",
                        tr("STRING<br />"
                        "Sets the permissions on the unix socket to the specified mode.<br />"
                        "Default: socket is world readable and writable"), "066");
    tabNetSockScrollAreaWidgetVBox->addWidget(cntLocalSocketMode);

    //FixStaleSocket
    cntFixStaleSocket = new CheckBoxPlug("FixStaleSocket",
                        tr("BOOL<br />"
                        "Remove stale socket after unclean shutdown.<br />"
                        "Default: yes"), true);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntFixStaleSocket);

    //TCPSocket
    cntTCPSocket = new SpinBoxPlug("TCPSocket",
                        tr("NUMBER<br />"
                        "TCP port number the daemon will listen on.<br />"
                        "Default: disabled"),
                        1, 65535, 3310);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntTCPSocket);

    //TCPAddr
    cntTCPAddr = new StringListWidgetPlug("TCPAddr",
                        tr("STRING<br />"
                        "By default clamd binds to INADDR_ANY.<br />"
                        "This option allows you to restrict the TCP address and provide<br />"
                        "some degree of protection from the outside world."
                        "Default: localhost"));
    tabNetSockScrollAreaWidgetVBox->addWidget(cntTCPAddr);

    //MaxConnectionQueueLength
    cntMaxConnectionQueueLength = new SpinBoxPlug("MaxConnectionQueueLength",
                        tr("NUMBER<br />"
                        "Maximum length the queue of pending connections may grow to.<br />"
                        "Default: 200"),
                        0, 2147483647, 30);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntMaxConnectionQueueLength);

    //StreamMaxLength
    cntStreamMaxLength = new SpinBoxPlug("StreamMaxLength",
                        tr("SIZE<br />"
                           "Close the STREAM session when the data size limit is exceeded.<br />"
                           "The value should match your MTA's limit for the maximum attachment size.<br />"
                           "Default: 25M"),
                        0, 2147483647, 25000000);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntStreamMaxLength);

    //StreamMinPort
    cntStreamMinPort = new SpinBoxPlug("StreamMinPort",
                        tr("NUMBER<br />"
                           "The STREAM command uses an FTP-like protocol.<br />"
                           "This option sets the lower boundary for the port range.<br />"
                           "Default: 1024"),
                        1, 65535, 1024);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntStreamMinPort);

    //StreamMaxPort
    cntStreamMaxPort = new SpinBoxPlug("StreamMaxPort",
                        tr("NUMBER<br />"
                           "This option sets the upper boundary for the port range.<br />"
                           "Default: 2048"),
                        1, 65535, 2048);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntStreamMaxPort);

    //MaxThreads
    cntMaxThreads = new SpinBoxPlug("MaxThreads",
                        tr("NUMBER<br />"
                           "Maximum number of threads running at the same time.<br />"
                           "Default: 10"),
                        0, 2147483647, 20);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntMaxThreads);

    //ReadTimeout
    cntReadTimeout = new SpinBoxPlug("ReadTimeout",
                        tr("NUMBER<br />"
                           "This option specifies the time (in seconds) after which clamd should timeout if a client doesn't provide any data.<br />"
                           "Default: 120"),
                        0, 2147483647, 120);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntReadTimeout);

    //CommandReadTimeout
    cntCommandReadTimeout = new SpinBoxPlug("CommandReadTimeout",
                        tr("NUMBER<br />"
                           "This option specifies the time (in seconds) after which clamd should timeout if a client doesn't provide any initial command after connecting. The default is set to 30 to avoid timeouts with TCP sockets when processing large messages. If using a Unix socket, the value can be changed to 5. Note: the timeout for subsequents commands, and/or data chunks is specified by ReadTimeout.<br />"
                           "Default: 30"),
                        0, 2147483647, 30);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntCommandReadTimeout);

    //SendBufTimeout
    cntSendBufTimeout = new SpinBoxPlug("SendBufTimeout",
                        tr("NUMBER<br />"
                           "This option specifies how long to wait (in milliseconds) if the send buffer is full. Keep this value low to prevent clamd hanging.<br />"
                           "Default: 500"),
                        0, 2147483647, 200);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntSendBufTimeout);

    //MaxQueue
    cntMaxQueue = new SpinBoxPlug("MaxQueue",
                        tr("NUMBER<br />"
                           "Maximum number of queued items (including those being processed by MaxThreads threads). It is recommended to have this value at least twice MaxThreads if possible.<br />"
                           "WARNING: you shouldn't increase this too much to avoid running out of file descriptors, the following condition should hold: MaxThreads*MaxRecursion + MaxQueue - MaxThreads + 6 &lt; RLIMIT_NOFILE. RLIMIT_NOFILE is the maximum number of open file descriptors (usually 1024), set by ulimit -n.<br />"
                           "Default: 100"),
                        0, 2147483647, 200);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntMaxQueue);

    //IdleTimeout
    cntIdleTimeout = new SpinBoxPlug("IdleTimeout",
                        tr("NUMBER<br />"
                           "This option specifies how long (in seconds) the process should wait for a new job.<br />"
                           "Default: 30"),
                        0, 2147483647, 60);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntIdleTimeout);

    //ExcludePath
    cntExcludePath = new StringListWidgetPlug("ExcludePath",
                        tr("REGEX<br />"
                        "Don't scan files and directories matching REGEX. This directive can be used multiple times.<br />"
                        "Default: disabled"));
    tabNetSockScrollAreaWidgetVBox->addWidget(cntExcludePath);

    //ConcurrentDatabaseReload
    cntConcurrentDatabaseReload = new CheckBoxPlug("ConcurrentDatabaseReload",
                        tr("BOOL<br />"
                        "Enable non-blocking (multi-threaded/concurrent) database reloads. This feature <br />"
                        "will temporarily load a second scanning engine while scanning continues using <br />"
                        "the first engine. Once loaded, the new engine takes over. The old engine is <br />"
                        "removed as soon as all scans using the old engine have completed. This feature <br />"
                        "requires more RAM, so this option is provided in case users are willing to <br />"
                        "block scans during reload in exchange for lower RAM requirements.<br />"
                        "Default: yes"), true);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntConcurrentDatabaseReload);

    //StructuredCCOnly
    cntStructuredCCOnly = new CheckBoxPlug("StructuredCCOnly",
                        tr("BOOL<br />"
                        "With this option enabled the DLP module will search for valid Credit Card<br />"
                        "numbers only. Debit and Private Label cards will not be searched.<br />"
                        "Default: yes"), true);
    tabNetSockScrollAreaWidgetVBox->addWidget(cntStructuredCCOnly);

    tabNetSockScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_logs_tab_init(){
    tabLogs = new QWidget();
    tabWidgetClamd->addTab(tabLogs, tr("Logs"));

    QVBoxLayout *tabLogsVBox = new QVBoxLayout();
    tabLogs->setLayout(tabLogsVBox);

    tabLogsScrollArea = new QScrollArea();
    tabLogsScrollArea->setWidgetResizable(true);
    tabLogsVBox->addWidget(tabLogsScrollArea);

    tabLogsScrollAreaWidget = new QWidget();
    tabLogsScrollArea->setWidget(tabLogsScrollAreaWidget);

    QVBoxLayout *tabLogsScrollAreaWidgetVBox = new QVBoxLayout();
    tabLogsScrollAreaWidget->setLayout(tabLogsScrollAreaWidgetVBox);

    ////

    //LogFile
    cntLogFile = new LineEditPlug("LogFile",
                        tr("STRING<br />"
                        "Save all reports to a log file.<br />"
                        "Default: disabled"), "/tmp/clamav.log");
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogFile);

    //LogFileUnlock
    cntLogFileUnlock = new CheckBoxPlug("LogFileUnlock",
                        tr("BOOL<br />"
                        "By default the log file is locked for writing and only a single daemon process can write to it. This option disables the lock.<br />"
                        "Default: no"), false);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogFileUnlock);

    //LogFileMaxSize
    cntLogFileMaxSize = new SpinBoxPlug("LogFileMaxSize",
                        tr("SIZE<br />"
                           "Maximum size of the log file.<br />"
                           "Value of 0 disables the limit.<br />"
                           "Default: 1048576"),
                        0, 2147483647, 1048576, 16);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogFileMaxSize);

    //LogTime
    cntLogTime = new CheckBoxPlug("LogTime",
                        tr("BOOL<br />"
                           "Log time for each message.<br />"
                           "Default: no"), false);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogTime);

    //LogClean
    cntLogClean = new CheckBoxPlug("LogClean",
                        tr("BOOL<br />"
                           "Log all clean files.<br />"
                           "Useful in debugging but drastically increases the log size.<br />"
                           "Default: no"), false);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogClean);

    //LogSyslog
    cntLogSyslog = new CheckBoxPlug("LogSyslog",
                        tr("BOOL<br />"
                           "Use the system logger (can work together with LogFile).<br />"
                           "Default: no"), false);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogSyslog);

    //LogFacility
    cntLogFacility = new LineEditPlug("LogFacility",
                        tr("SSTRING<br />"
                           "Type of syslog messages<br />"
                           "Please refer to 'man syslog' for facility names.<br />"
                           "Default: LOG_LOCAL6"), "LOG_MAIL");
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogFacility);

    //LogVerbose
    cntLogVerbose = new CheckBoxPlug("LogVerbose",
                        tr("BOOL<br />"
                           "Use the system logger (can work together with LogFile).<br />"
                           "Default: no"), false);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogVerbose);

    //LogRotate
    cntLogRotate = new CheckBoxPlug("LogRotate",
                        tr("BOOL<br />"
                           "Rotate log file. Requires LogFileMaxSize option set prior to this option.<br />"
                           "Default: no"), false);
    tabLogsScrollAreaWidgetVBox->addWidget(cntLogRotate);

    tabLogsScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_parameters_tab_init(){
    tabParameters = new QWidget();
    tabWidgetClamd->addTab(tabParameters, tr("Parameters"));

    QVBoxLayout *tabParametersVBox = new QVBoxLayout();
    tabParameters->setLayout(tabParametersVBox);

    tabParametersScrollArea = new QScrollArea();
    tabParametersScrollArea->setWidgetResizable(true);
    tabParametersVBox->addWidget(tabParametersScrollArea);

    tabParametersScrollAreaWidget = new QWidget();
    tabParametersScrollArea->setWidget(tabParametersScrollAreaWidget);

    QVBoxLayout *tabParametersScrollAreaWidgetVBox = new QVBoxLayout();
    tabParametersScrollAreaWidget->setLayout(tabParametersScrollAreaWidgetVBox);

    //ExtendedDetectionInfo
    cntExtendedDetectionInfo = new CheckBoxPlug("ExtendedDetectionInfo",
                        tr("BOOL<br />"
                           "Log additional information about the infected file, such as its size and hash, together with the virus name.<br />"
                           "Default: no"), false);
    tabParametersScrollAreaWidgetVBox->addWidget(cntExtendedDetectionInfo);

    //PidFile
    cntPidFile = new LineEditPlug("PidFile",
                           tr("STRING<br />"
                              "Save the process identifier of a listening daemon (main thread) to a specified file.<br />"
                              "Default: disabled<br />"), "/var/run/clam.pid");
    tabParametersScrollAreaWidgetVBox->addWidget(cntPidFile);

    //TemporaryDirectory
    cntTemporaryDirectory = new LineEditPlug("TemporaryDirectory",
                           tr("STRING<br />"
                              "This option allows you to change the default temporary directory.<br />"
                              "Default: system specific (usually /tmp or /var/tmp)."), "/tmp");
    tabParametersScrollAreaWidgetVBox->addWidget(cntTemporaryDirectory);

    //DatabaseDirectory
    cntDatabaseDirectory = new LineEditPlug("DatabaseDirectory",
                           tr("STRING<br />"
                              "This option allows you to change the default database directory. If you enable it, please make sure it points to the same directory in both clamd and freshclam.<br />"
                              "Default: defined at configuration (/usr/local/share/clamav)"), "/var/lib/clamav");
    tabParametersScrollAreaWidgetVBox->addWidget(cntDatabaseDirectory);

    //OfficialDatabaseOnly
    cntOfficialDatabaseOnly = new CheckBoxPlug("OfficialDatabaseOnly",
                        tr("BOOL<br />"
                           "Only load the official signatures published by the ClamAV project.<br />"
                           "Default: no"), false);
    tabParametersScrollAreaWidgetVBox->addWidget(cntOfficialDatabaseOnly);

    //StatsEnabled
    cntStatsEnabled = new CheckBoxPlug("StatsEnabled",
                        tr("BOOL<br />"
                        "Enable submission of statistical data.<br />"
                        "Default: yes"), true);
    tabParametersScrollAreaWidgetVBox->addWidget(cntStatsEnabled);

    //StatsHostID
    cntStatsHostID = new LineEditPlug("StatsHostID",
                        tr("STRING<br />"
                        "HostID in the form of an UUID to use when submitting statistical information. See the clamscan manpage for more information.<br />"
                        "Default: default<br />"), "default");
    tabParametersScrollAreaWidgetVBox->addWidget(cntStatsHostID);

    //StatsPEDisabled
    cntStatsPEDisabled = new CheckBoxPlug("StatsPEDisabled",
                        tr("BOOL<br />"
                        "Disable submission of PE section statistical data.<br />"
                        "Default: no"), false);
    tabParametersScrollAreaWidgetVBox->addWidget(cntStatsPEDisabled);

    //StatsTimeout
    cntStatsTimeout = new SpinBoxPlug("StatsTimeout",
                        tr("NUMBER<br />"
                           "Timeout in seconds to timeout communication with the stats server.<br />"
                           "Default: 10"),
                        0, 2147483647, 10);
    tabParametersScrollAreaWidgetVBox->addWidget(cntStatsTimeout);

    //AlgorithmicDetection
    cntAlgorithmicDetection = new CheckBoxPlug("AlgorithmicDetection",
                        tr("BOOL<br />"
                        "In some cases (eg. complex malware, exploits in graphic files, and others),<br />"
                        "ClamAV uses special algorithms to provide accurate detection. This option<br />"
                        "controls the algorithmic detection.<br />"
                        "Default: yes"), true);
    tabParametersScrollAreaWidgetVBox->addWidget(cntAlgorithmicDetection);

    //ArchiveBlockEncrypted
    cntArchiveBlockEncrypted = new CheckBoxPlug("ArchiveBlockEncrypted",
                        tr("BOOL<br />"
                        "Mark encrypted archives as viruses (Encrypted.Zip, Encrypted.RAR).<br />"
                        "Default: no"), false);
    tabParametersScrollAreaWidgetVBox->addWidget(cntArchiveBlockEncrypted);


    tabParametersScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_filesys_tab_init(){
    tabFileSys = new QWidget();
    tabWidgetClamd->addTab(tabFileSys, tr("FileSys"));

    QVBoxLayout *tabFileSysVBox = new QVBoxLayout();
    tabFileSys->setLayout(tabFileSysVBox);

    tabFileSysScrollArea = new QScrollArea();
    tabFileSysScrollArea->setWidgetResizable(true);
    tabFileSysVBox->addWidget(tabFileSysScrollArea);

    tabFileSysScrollAreaWidget = new QWidget();
    tabFileSysScrollArea->setWidget(tabFileSysScrollAreaWidget);

    QVBoxLayout *tabFileSysScrollAreaWidgetVBox = new QVBoxLayout();
    tabFileSysScrollAreaWidget->setLayout(tabFileSysScrollAreaWidgetVBox);

    //MaxDirectoryRecursion
    cntMaxDirectoryRecursion = new SpinBoxPlug("MaxDirectoryRecursion",
                        tr("NUMBER<br />"
                           "Maximum depth directories are scanned at.<br />"
                           "Default: 15"),
                        0, 99, 15);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntMaxDirectoryRecursion);

    //FollowDirectorySymlinks
    cntFollowDirectorySymlinks = new CheckBoxPlug("FollowDirectorySymlinks",
                        tr("BOOL<br />"
                           "Follow regular file symlinks.<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntFollowDirectorySymlinks);

    //CheckBoxPlug FollowFileSymlinks
    cntFollowFileSymlinks = new CheckBoxPlug("FollowFileSymlinks",
                        tr("BOOL<br />"
                           "Follow regular file symlinks.<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntFollowFileSymlinks);

    //CrossFilesystems
    cntCrossFilesystems = new CheckBoxPlug("CrossFilesystems",
                        tr("BOOL<br />"
                           "Scan files and directories on other filesystems.<br />"
                           "Default: yes"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntCrossFilesystems);

    //SelfCheck
    cntSelfCheck = new SpinBoxPlug("SelfCheck",
                        tr("NUMBER<br />"
                           "Maximum depth directories are scanned at.<br />"
                           "Default: 15"),
                        0, 2147483647, 600);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntSelfCheck);

    //DisableCache
    cntDisableCache = new CheckBoxPlug("DisableCache",
                        tr("BOOL<br />"
                           "This option allows you to disable clamd's caching feature.<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntDisableCache);

    //VirusEvent
    cntVirusEvent = new LineEditPlug("VirusEvent",
                           tr("COMMAND<br />"
                              "Execute a command when a virus is found. In the command string %v will be<br />replaced with the virus name and %f will be replaced with the file name.<br />Additionally, two environment variables will be defined: $CLAM_VIRUSEVENT_FILENAME<br />and $CLAM_VIRUSEVENT_VIRUSNAME.<br />"
                              "Default: disabled"), "/usr/bin/mailx -s \"ClamAV VIRUS ALERT: %v\" alert < /dev/null");
    tabFileSysScrollAreaWidgetVBox->addWidget(cntVirusEvent);

    //CheckBoxPlug ExitOnOOM
    cntExitOnOOM = new CheckBoxPlug("ExitOnOOM",
                        tr("BBOOL<br />"
                           "Stop daemon when libclamav reports out of memory condition.<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntExitOnOOM);

    //CheckBoxPlug AllowAllMatchScan
    cntAllowAllMatchScan = new CheckBoxPlug("AllowAllMatchScan",
                        tr("BOOL<br />"
                           "Permit use of the ALLMATCHSCAN command.<br />"
                           "Default: yes"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntAllowAllMatchScan);

    //CheckBoxPlug Foreground
    cntForeground = new CheckBoxPlug("Foreground",
                        tr("BOOL<br />"
                           "Don't fork into background.<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntForeground);

    //CheckBoxPlug Debug
    cntDebug = new CheckBoxPlug("Debug",
                        tr("BOOL<br />"
                           "Enable debug messages from libclamav.<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntDebug);

    //CheckBoxPlug LeaveTemporaryFiles
    cntLeaveTemporaryFiles = new CheckBoxPlug("LeaveTemporaryFiles",
                        tr("BOOL<br />"
                           "Do not remove temporary files (for debugging purpose).<br />"
                           "Default: no"), false);
    tabFileSysScrollAreaWidgetVBox->addWidget(cntLeaveTemporaryFiles);

    tabFileSysScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_scanning_tab_init(){
    tabScanning = new QWidget();
    tabWidgetClamd->addTab(tabScanning, tr("Scanning"));

    QVBoxLayout *tabScanningVBox = new QVBoxLayout();
    tabScanning->setLayout(tabScanningVBox);

    tabScanningScrollArea = new QScrollArea();
    tabScanningScrollArea->setWidgetResizable(true);
    tabScanningVBox->addWidget(tabScanningScrollArea);

    tabScanningScrollAreaWidget = new QWidget();
    tabScanningScrollArea->setWidget(tabScanningScrollAreaWidget);

    QVBoxLayout *tabScanningScrollAreaWidgetVBox = new QVBoxLayout();
    tabScanningScrollAreaWidget->setLayout(tabScanningScrollAreaWidgetVBox);

    //User
    cntUser = new LineEditPlug("User",
                        tr("STRING<br />"
                        "Run the daemon as a specified user (the process must be started by root).<br />"
                        "Default: disabled"), "/usr/bin/mailx -s \"ClamAV VIRUS ALERT: %v\" alert < /dev/null");
    tabScanningScrollAreaWidgetVBox->addWidget(cntUser);

    //AllowSupplementaryGroups
    cntAllowSupplementaryGroups = new CheckBoxPlug("AllowSupplementaryGroups",
                        tr("BOOL<br />"
                        "Initialize a supplementary group access (the process must be started by root).<br />"
                        "Default: no"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntAllowSupplementaryGroups);

    //MailFollowURLs
    cntMailFollowURLs = new CheckBoxPlug("MailFollowURLs",
                        tr("BOOL<br />"
                           "If an email contains URLs ClamAV can download and scan them.<br />"
                           "WARNING: This option may open your system to a DoS attack. Please don't use<br />"
                           "this feature on highly loaded servers.<br />"
                        "Default: no"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntMailFollowURLs);


    //Bytecode
    cntBytecode = new CheckBoxPlug("Bytecode",
                        tr("BOOL<br />"
                        "With this option enabled ClamAV will load bytecode from the database. It is highly recommended you keep this option turned on, otherwise you may miss detections for many new viruses.<br />"
                        "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntBytecode);

    //
    cntBytecodeSecurity = new ComboBoxPlug("BytecodeSecurity",
                        tr("STRING<br />"
                        "Set bytecode security level.<br />"
                        "<br />"
                        "Possible values:<br />"
                        "TrustSigned - trust bytecode loaded from signed .c[lv]d files and insert runtime safety checks for bytecode loaded from other sources,<br />"
                        "Paranoid - don't trust any bytecode, insert runtime checks for all.<br />"
                        "Recommended: TrustSigned, because bytecode in .cvd files already has these checks.<br />"
                        "Default: TrustSigned"),
                        QStringList() << "TrustSigned" << "Paranoid");
    tabScanningScrollAreaWidgetVBox->addWidget(cntBytecodeSecurity);

    //
    cntBytecodeTimeout = new SpinBoxPlug("BytecodeTimeout",
                        tr("NUMBER<br />"
                           "Set bytecode timeout in milliseconds.<br />"
                           "Default: 10000"),
                        0, 2147483647, 10000);
    tabScanningScrollAreaWidgetVBox->addWidget(cntBytecodeTimeout);

    //BytecodeUnsigned
    cntBytecodeUnsigned = new CheckBoxPlug("BytecodeUnsigned",
                        tr("BOOL<br />"
                           "Allow loading bytecode from outside digitally signed .c[lv]d files.<br />"
                           "Default: no"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntBytecodeUnsigned);

    //BytecodeMode
    cntBytecodeMode = new ComboBoxPlug("BytecodeMode",
                        tr("STRING<br />"
                           "Set bytecode execution mode.<br />"
                           "<br />"
                           "Possible values:<br />"
                           "Auto - automatically choose JIT if possible, fallback to interpreter<br />"
                           "ForceJIT - always choose JIT, fail if not possible<br />"
                           "ForceInterpreter - always choose interpreter<br />"
                           "Test - run with both JIT and interpreter and compare results. Make all failures fatal.<br />"
                           "Default: Auto"),
                        QStringList() << "Auto" << "ForceJIT" << "ForceInterpreter" << "Test");
    tabScanningScrollAreaWidgetVBox->addWidget(cntBytecodeMode);

    //DetectPUA
    cntDetectPUA = new CheckBoxPlug("DetectPUA",
                        tr("BOOL<br />"
                           "Detect Possibly Unwanted Applications.<br />"
                           "Default: No"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntDetectPUA);

    //ExcludePUA
    cntExcludePUA = new StringListWidgetPlug("ExcludePUA",
                        tr("CATEGORY<br />"
                           "Exclude a specific PUA category. This directive can be used multiple times.<br />See https://docs.clamav.net/faq/faq-pua.html for the complete list of PUA\ncategories.<br />"
                           "Default: disabled"));
    tabScanningScrollAreaWidgetVBox->addWidget(cntExcludePUA);

    //IncludePUA
    cntIncludePUA = new StringListWidgetPlug("IncludePUA",
                        tr("CATEGORY<br />"
                           "Only include a specific PUA category. This directive can be used multiple times. See https://www.clamav.net/documents/potentially-unwanted-applications-pua for the complete list of PUA categories.<br />"
                           "Default: disabled"));
    tabScanningScrollAreaWidgetVBox->addWidget(cntIncludePUA);

    //DetectBrokenExecutables
    cntDetectBrokenExecutables = new CheckBoxPlug("DetectBrokenExecutables",
                        tr("BOOL<br />"
                        "With this option enabled clamav will try to detect broken executables<br />"
                        "(both PE and ELF) and mark them as Broken.Executable.<br />"
                        "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntDetectBrokenExecutables);

    //ScanPE
    cntScanPE = new CheckBoxPlug("ScanPE",
                        tr("BOOL<br />"
                           "PE stands for Portable Executable - it's an executable file format used in all 32 and 64-bit versions of Windows operating systems. This option allows ClamAV to perform a deeper analysis of executable files and it's also required for decompression of popular executable packers such as UPX.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanPE);

    //ScanELF
    cntScanELF = new CheckBoxPlug("ScanELF",
                        tr("BOOL<br />"
                           "Executable and Linking Format is a standard format for UN*X executables. This option allows you to control the scanning of ELF files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanELF);

    //ScanMail
    cntScanMail = new CheckBoxPlug("ScanMail",
                        tr("BOOL<br />"
                           "Enable scanning of mail files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without parsing individual messages/attachments.<br />"
                           "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanMail);

    //ScanPartialMessages
    cntScanPartialMessages = new CheckBoxPlug("ScanPartialMessages",
                        tr("BOOL<br />"
                           "Scan RFC1341 messages split over many emails. You will need to periodically clean up $TemporaryDirectory/clamav-partial directory. WARNING: This option may open your system to a DoS attack. Never use it on loaded servers.<br />"
                           "Default: no"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanPartialMessages);

    //PhishingSignatures
    cntPhishingSignatures = new CheckBoxPlug("PhishingSignatures",
                        tr("BOOL<br />"
                           "Enable email signature-based phishing detection.<br />"
                           "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntPhishingSignatures);

    //PhishingScanURLs
    cntPhishingScanURLs = new CheckBoxPlug("PhishingScanURLs",
                        tr("BOOL<br />"
                           "Enable URL signature-based phishing detection (Phishing.Heuristics.Email.*)<br />"
                           "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntPhishingScanURLs);

    //PartitionIntersection
    cntPartitionIntersection = new CheckBoxPlug("PartitionIntersection",
                        tr("BOOL<br />"
                           "Detect partition intersections in raw disk images using heuristics.<br />"
                           "Default: yes"), true);
    tabScanningScrollAreaWidgetVBox->addWidget(cntPartitionIntersection);

    //HeuristicAlerts
    cntHeuristicAlerts = new CheckBoxPlug("HeuristicAlerts",
                        tr("BOOL<br />"
                           "In some cases (eg. complex malware, exploits in graphic files, and others), ClamAV uses special algorithms to provide accurate detection. This option controls the algorithmic detection.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntHeuristicAlerts);

    //HeuristicScanPrecedence
    cntHeuristicScanPrecedence = new CheckBoxPlug("HeuristicScanPrecedence",
                        tr("BOOL<br />"
                           "Allow heuristic match to take precedence. When enabled, if a heuristic scan (such as phishingScan) detects a possible virus/phishing it will stop scanning immediately. Recommended, saves CPU scan-time. When disabled, virus/phishing detected by heuristic scans will be reported only at the end of a scan. If an archive contains both a heuristically detected virus/phishing, and a real malware, the real malware will be reported. Keep this disabled if you intend to handle \"*.Heuristics.*\" viruses differently from \"real\" malware. If a non-heuristically-detected virus (signature-based) is found first, the scan is interrupted immediately, regardless of this config option.<br />"
                           "Default: no"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntHeuristicScanPrecedence);

    //StructuredDataDetection
    cntStructuredDataDetection = new CheckBoxPlug("StructuredDataDetection",
                        tr("BOOL<br />"
                           "Enable the DLP module.<br />"
                           "Default: no"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntStructuredDataDetection);

    //StructuredMinCreditCardCount
    cntStructuredMinCreditCardCount = new SpinBoxPlug("StructuredMinCreditCardCount",
                        tr("NUMBER<br />"
                           "This option sets the lowest number of Credit Card numbers found in a file to generate a detect.<br />"
                           "Default: 3"),
                        0, 2147483647, 5);
    tabScanningScrollAreaWidgetVBox->addWidget(cntStructuredMinCreditCardCount);

    //StructuredMinSSNCount
    cntStructuredMinSSNCount = new SpinBoxPlug("StructuredMinSSNCount",
                        tr("NUMBER<br />"
                           "This option sets the lowest number of Social Security Numbers found in a file to generate a detect.<br />"
                           "Default: 3"),
                        0, 2147483647, 5);
    tabScanningScrollAreaWidgetVBox->addWidget(cntStructuredMinSSNCount);

    //StructuredSSNFormatNormal
    cntStructuredSSNFormatNormal = new CheckBoxPlug("StructuredSSNFormatNormal",
                        tr("BOOL<br />"
                           "With this option enabled the DLP module will search for valid SSNs formatted as xxx-yy-zzzz.<br />"
                           "Default: Yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntStructuredSSNFormatNormal);

    //StructuredSSNFormatStripped
    cntStructuredSSNFormatStripped = new CheckBoxPlug("StructuredSSNFormatStripped",
                        tr("BOOL<br />"
                           "With this option enabled the DLP module will search for valid SSNs formatted as xxxyyzzzz.<br />"
                           "Default: No"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntStructuredSSNFormatStripped);

    //ScanHTML
    cntScanHTML = new CheckBoxPlug("ScanHTML",
                        tr("BOOL<br />"
                           "Perform HTML/JavaScript/ScriptEncoder normalisation and decryption.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanHTML);

    //ScanOLE2
    cntScanOLE2 = new CheckBoxPlug("ScanOLE2",
                        tr("BOOL<br />"
                           "This option enables scanning of OLE2 files, such as Microsoft Office documents and .msi files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanOLE2);

    //ScanPDF
    cntScanPDF = new CheckBoxPlug("ScanPDF",
                        tr("BOOL<br />"
                           "This option enables scanning within PDF files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanPDF);

    //ScanSWF
    cntScanSWF = new CheckBoxPlug("ScanSWF",
                        tr("BOOL<br />"
                           "This option enables scanning within SWF files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without decoding and additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanSWF);

    //ScanXMLDOCS
    cntScanXMLDOCS = new CheckBoxPlug("ScanXMLDOCS",
                        tr("BOOL<br />"
                           "This option enables scanning xml-based document files supported by libclamav.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanXMLDOCS);

    //ScanHWP3
    cntScanHWP3 = new CheckBoxPlug("ScanHWP3",
                        tr("BOOL<br />"
                           "This option enables scanning HWP3 files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanHWP3);

    //ScanArchive
    cntScanArchive = new CheckBoxPlug("ScanArchive",
                        tr("BOOL<br />"
                           "Scan within archives and compressed files.<br />"
                           "If you turn off this option, the original files will still be scanned, but without unpacking and additional processing.<br />"
                           "Default: yes"), false);
    tabScanningScrollAreaWidgetVBox->addWidget(cntScanArchive);

    tabScanningScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_alerts_tab_init(){
    tabAlerts = new QWidget();
    tabWidgetClamd->addTab(tabAlerts, tr("Alerts"));

    QVBoxLayout *tabAlertsVBox = new QVBoxLayout();
    tabAlerts->setLayout(tabAlertsVBox);

    tabAlertsScrollArea = new QScrollArea();
    tabAlertsScrollArea->setWidgetResizable(true);
    tabAlertsVBox->addWidget(tabAlertsScrollArea);

    tabAlertsScrollAreaWidget = new QWidget();
    tabAlertsScrollArea->setWidget(tabAlertsScrollAreaWidget);

    QVBoxLayout *tabAlertsScrollAreaWidgetVBox = new QVBoxLayout();
    tabAlertsScrollAreaWidget->setLayout(tabAlertsScrollAreaWidgetVBox);

    //AlertBrokenExecutables
    cntAlertBrokenExecutables = new CheckBoxPlug("AlertBrokenExecutables",
                        tr("BOOL<br />"
                           "With this option enabled clamav will try to detect broken executables<br />"
                           "(PE, ELF, & Mach-O) and alert on them with a Broken.Executable heuristic signature.<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertBrokenExecutables);

    //AlertEncrypted
    cntAlertEncrypted = new CheckBoxPlug("AlertEncrypted",
                        tr("BOOL<br />"
                           "Alert on encrypted archives and documents (encrypted .zip, .7zip, .rar, .pdf).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertEncrypted);

    //AlertEncryptedArchive
    cntAlertEncryptedArchive = new CheckBoxPlug("AlertEncryptedArchive",
                        tr("BOOL<br />"
                           "Alert on encrypted archives (encrypted .zip, .7zip, .rar).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertEncryptedArchive);

    //AlertEncryptedDoc
    cntAlertEncryptedDoc = new CheckBoxPlug("AlertEncryptedDoc",
                        tr("BOOL<br />"
                           "Alert on encrypted documents (encrypted .pdf).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertEncryptedDoc);

    //AlertOLE2Macros
    cntAlertOLE2Macros = new CheckBoxPlug("AlertOLE2Macros",
                        tr("BOOL<br />"
                           "Alert on OLE2 files containing VBA macros (Heuristics.OLE2.ContainsMacros).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertOLE2Macros);

    //AlertExceedsMax
    cntAlertExceedsMax = new CheckBoxPlug("AlertExceedsMax",
                        tr("BOOL<br />"
                           "Alert on files that exceed max file size, max scan size, or max recursion limit (Heuristics.Limits.Exceeded).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertExceedsMax);

    //AlertPhishingSSLMismatch
    cntAlertPhishingSSLMismatch = new CheckBoxPlug("AlertPhishingSSLMismatch",
                        tr("BOOL<br />"
                           "Alert on emails containing SSL mismatches in URLs (might lead to false positives!).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertPhishingSSLMismatch);

    //AlertPhishingCloak
    cntAlertPhishingCloak = new CheckBoxPlug("AlertPhishingCloak",
                        tr("BOOL<br />"
                           "Alert on emails containing cloaked URLs (might lead to some false positives).<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertPhishingCloak);

    //PhishingAlwaysBlockCloak
    cntPhishingAlwaysBlockCloak = new CheckBoxPlug("PhishingAlwaysBlockCloak",
                        tr("BOOL<br />"
                        "Always block cloaked URLs, even if they're not in the database.<br />"
                        "This feature can lead to false positives.<br />"
                        "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntPhishingAlwaysBlockCloak);

    //PhishingAlwaysBlockSSLMismatch
    cntPhishingAlwaysBlockSSLMismatch = new CheckBoxPlug("PhishingAlwaysBlockSSLMismatch",
                        tr("BOOL<br />"
                        "Always block SSL mismatches in URLs, even if they're not in the database.<br />"
                        "This feature can lead to false positives.<br />"
                        "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntPhishingAlwaysBlockSSLMismatch);

    //AlertPartitionIntersection
    cntAlertPartitionIntersection = new CheckBoxPlug("AlertPartitionIntersection",
                        tr("BOOL<br />"
                           "Alert on raw DMG image files containing partition intersections.<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntAlertPartitionIntersection);

    //ForceToDisk
    cntForceToDisk = new CheckBoxPlug("ForceToDisk",
                        tr("BOOL<br />"
                           "This option causes memory or nested map scans to dump the content to disk.<br />"
                           "If you turn on this option, more data is written to disk and is available when the leave-temps option is enabled at the cost of more disk writes.<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntForceToDisk);

    //MaxScanTime
    cntMaxScanTime = new SpinBoxPlug("MaxScanTime",
                        tr("SIZE<br />"
                           "This option sets the maximum amount of time a scan may take to complete.<br />"
                           "In this version, this field only affects the scan time of ZIP archives.<br />"
                           "The value of 0 disables the limit.<br />"
                           "WARNING: disabling this limit or setting it too high may result allow scanning of certain files to lock up the scanning process/threads resulting in a Denial of Service.<br />"
                           "The value is in milliseconds.<br />"
                           "Default: 0"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxScanTime);

    //MaxScanSize
    cntMaxScanSize = new SpinBoxPlug("MaxScanSize",
                        tr("SIZE<br />"
                           "Sets the maximum amount of data to be scanned for each input file. Archives and other containers are recursively extracted and scanned up to this value. The size of an archive plus the sum of the sizes of all files within archive count toward the scan size. For example, a 1M uncompressed archive containing a single 1M inner file counts as 2M toward the max scan size. Warning: disabling this limit or setting it too high may result in severe damage to the system.<br />"
                           "Default: 100M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxScanSize);

    //MaxFileSize
    cntMaxFileSize = new SpinBoxPlug("MaxFileSize",
                        tr("SIZE<br />"
                           "Files larger than this limit won't be scanned. Affects the input file itself as well as files contained inside it (when the input file is an archive, a document or some other kind of container). Warning: disabling this limit or setting it too high may result in severe damage to the system.<br />"
                           "Default: 25M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxFileSize);

    //BlockMax
    cntBlockMax = new CheckBoxPlug("BlockMax",
                        tr("BOOL<br />"
                           "Flag files with \"Heuristics.Limits.Exceeded\" when scanning is<br />"
                           "incomplete due to exceeding a scan or file size limit.<br />"
                           "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntBlockMax);

    //OLE2BlockMacros
    cntOLE2BlockMacros = new CheckBoxPlug("OLE2BlockMacros",
                        tr("BOOL<br />"
                        "With this option enabled OLE2 files with VBA macros, which were not<br />"
                        "detected by signatures will be marked as \"Heuristics.OLE2.ContainsMacros\".<br />"
                        "Default: no"), false);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntOLE2BlockMacros);

    //MaxRecursion
    cntMaxRecursion = new SpinBoxPlug("MaxRecursion",
                        tr("NUMBER<br />"
                           "Nested archives are scanned recursively, e.g. if a Zip archive contains a RAR file, all files within it will also be scanned. This options specifies how deeply the process should be continued. Warning: setting this limit too high may result in severe damage to the system.<br />"
                           "Default: 17"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxRecursion);

    //MaxFiles
    cntMaxFiles = new SpinBoxPlug("MaxFiles",
                        tr("NUMBER<br />"
                           "Number of files to be scanned within an archive, a document, or any other kind of container. Warning: disabling this limit or setting it too high may result in severe damage to the system.<br />"
                           "Default: 10000"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxFiles);

    //MaxEmbeddedPE
    cntMaxEmbeddedPE = new SpinBoxPlug("MaxEmbeddedPE",
                        tr("SIZE<br />"
                           "This option sets the maximum size of a file to check for embedded PE.<br />"
                           "Files larger than this value will skip the additional analysis step.<br />"
                           "Negative values are not allowed.<br />"
                           "Default: 10M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxEmbeddedPE);

    //MaxHTMLNormalize
    cntMaxHTMLNormalize = new SpinBoxPlug("MaxHTMLNormalize",
                        tr("SIZE<br />"
                           "This option sets the maximum size of a HTML file to normalize.<br />"
                           "HTML files larger than this value will not be normalized or scanned.<br />"
                           "Negative values are not allowed.<br />"
                           "Default: 10M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxHTMLNormalize);

    //MaxHTMLNoTags
    cntMaxHTMLNoTags = new SpinBoxPlug("MaxHTMLNoTags",
                        tr("SIZE<br />"
                           "This option sets the maximum size of a normalized HTML file to scan.<br />"
                           "HTML files larger than this value after normalization will not be scanned.<br />"
                           "Negative values are not allowed.<br />"
                           "Default: 2M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxHTMLNoTags);

    //MaxScriptNormalize
    cntMaxScriptNormalize = new SpinBoxPlug("MaxScriptNormalize",
                        tr("SIZE<br />"
                           "This option sets the maximum size of a script file to normalize.<br />"
                           "Script content larger than this value will not be normalized or scanned.<br />"
                           "Negative values are not allowed.<br />"
                           "Default: 5M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxScriptNormalize);

    //MaxZipTypeRcg
    cntMaxZipTypeRcg = new SpinBoxPlug("MaxZipTypeRcg",
                        tr("SIZE<br />"
                           "This option sets the maximum size of a ZIP file to reanalyze type recognition.<br />"
                           "ZIP files larger than this value will skip the step to potentially reanalyze as PE.<br />"
                           "Negative values are not allowed.<br />"
                           "WARNING: setting this limit too high may result in severe damage or impact performance.<br />"
                           "Default: 1M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxZipTypeRcg);

    //MaxPartitions
    cntMaxPartitions = new SpinBoxPlug("MaxPartitions",
                        tr("SIZE<br />"
                           "This option sets the maximum number of partitions of a raw disk image to be scanned.<br />"
                           "Raw disk images with more partitions than this value will have up to the value partitions scanned.<br />"
                           "Negative values are not allowed.<br />"
                           "WARNING: setting this limit too high may result in severe damage or impact performance.<br />"
                           "Default: 50"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxPartitions);

    //MaxIconsPE
    cntMaxIconsPE = new SpinBoxPlug("MaxIconsPE",
                        tr("SIZE<br />"
                           "This option sets the maximum number of icons within a PE to be scanned.<br />"
                           "PE files with more icons than this value will have up to the value number icons scanned.<br />"
                           "Negative values are not allowed.<br />"
                           "WARNING: setting this limit too high may result in severe damage or impact performance.<br />"
                           "Default: 100"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxIconsPE);

    //MaxRecHWP3
    cntMaxRecHWP3 = new SpinBoxPlug("MaxRecHWP3",
                        tr("NUMBER<br />"
                           "This option sets the maximum recursive calls to HWP3 parsing function.<br />"
                           "HWP3 files using more than this limit will be terminated and alert the user.<br />"
                           "Scans will be unable to scan any HWP3 attachments if the recursive limit is reached.<br />"
                           "Negative values are not allowed.<br />"
                           "WARNING: setting this limit too high may result in severe damage or impact performance.<br />"
                           "Default: 16"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntMaxRecHWP3);

    //PCREMatchLimit
    cntPCREMatchLimit = new SpinBoxPlug("PCREMatchLimit",
                        tr("NUMBER<br />"
                           "This option sets the maximum calls to the PCRE match function during an instance of regex matching.<br />"
                           "Instances using more than this limit will be terminated and alert the user but the scan will continue.<br />"
                           "For more information on match_limit, see the PCRE documentation.<br />"
                           "Negative values are not allowed.<br />"
                           "WARNING: setting this limit too high may severely impact performance.<br />"
                           "Default: 10000"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntPCREMatchLimit);

    //PCRERecMatchLimit
    cntPCRERecMatchLimit = new SpinBoxPlug("PCRERecMatchLimit",
                        tr("NUMBER<br />"
                           "This option sets the maximum recursive calls to the PCRE match function during an instance of regex matching.<br />"
                           "Instances using more than this limit will be terminated and alert the user but the scan will continue.<br />"
                           "For more information on match_limit_recursion, see the PCRE documentation.<br />"
                           "Negative values are not allowed and values > PCREMatchLimit are superfluous.<br />"
                           "WARNING: setting this limit too high may severely impact performance."
                           "Default: 2000"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntPCRERecMatchLimit);

    //PCREMaxFileSize
    cntPCREMaxFileSize = new SpinBoxPlug("PCREMaxFileSize",
                        tr("SIZE<br />"
                           "This option sets the maximum filesize for which PCRE subsigs will be executed.<br />"
                           "Files exceeding this limit will not have PCRE subsigs executed unless a subsig is encompassed to a smaller buffer.<br />"
                           "Negative values are not allowed.<br />"
                           "Setting this value to zero disables the limit.<br />"
                           "WARNING: setting this limit too high or disabling it may severely impact performance.<br />"
                           "Default: 25M"),
                        0, 2147483647, 5);
    tabAlertsScrollAreaWidgetVBox->addWidget(cntPCREMaxFileSize);


    tabAlertsScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_onaccess_tab_init(){
    tabOnAccess = new QWidget();
    tabWidgetClamd->addTab(tabOnAccess, tr("OnAccess"));

    QVBoxLayout *tabOnAccessVBox = new QVBoxLayout();
    tabOnAccess->setLayout(tabOnAccessVBox);

    tabOnAccessScrollArea = new QScrollArea();
    tabOnAccessScrollArea->setWidgetResizable(true);
    tabOnAccessVBox->addWidget(tabOnAccessScrollArea);

    tabOnAccessScrollAreaWidget = new QWidget();
    tabOnAccessScrollArea->setWidget(tabOnAccessScrollAreaWidget);

    QVBoxLayout *tabOnAccessScrollAreaWidgetVBox = new QVBoxLayout();
    tabOnAccessScrollAreaWidget->setLayout(tabOnAccessScrollAreaWidgetVBox);

    //ScanOnAccess
    cntScanOnAccess = new CheckBoxPlug("ScanOnAccess",
                        tr("BOOL<br />"
                           "This option enables on-access scanning (Linux only)<br />"
                           "Default: disabled"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntScanOnAccess);

    //OnAccessMountPath
    cntOnAccessMountPath = new StringListWidgetPlug("OnAccessMountPath",
                        tr("STRING<br />"
                           "Specifies a mount point (including all files and directories under it), which should be scanned on access. This option can be used multiple times.<br />"
                           "Default: disabled"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessMountPath);

    //OnAccessIncludePath
    cntOnAccessIncludePath = new StringListWidgetPlug("OnAccessIncludePath",
                        tr("STRING<br />"
                           "This option specifies a directory (including all files and directories inside it), which should be scanned on access. This option can be used multiple times.<br />"
                           "Default: disabled"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessIncludePath);

    //OnAccessExcludePath
    cntOnAccessExcludePath = new StringListWidgetPlug("OnAccessExcludePath",
                        tr("STRING<br />"
                           "This option allows excluding directories from on-access scanning. It can be used multiple times.<br />"
                           "Default: disabled"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessExcludePath);

    //OnAccessExcludeRootUID
    cntOnAccessExcludeRootUID = new CheckBoxPlug("OnAccessExcludeRootUID",
                        tr("BOOL<br />"
                           "Use this option to exclude the root UID (0) and allow any processes run under root to access all watched files without triggering scans.<br />"
                           "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessExcludeRootUID);

    //OnAccessExcludeUID
    cntOnAccessExcludeUID = new ListSpinBoxWidgetPlug("OnAccessExcludeUID",
                        tr("NUMBER<br />"
                           "With this option you can whitelist specific UIDs. Processes with these UIDs will be able to access all files without triggering scans or permission denied events.<br />"
                           "This option can be used multiple times (one per line).<br />"
                           "Note: using a value of 0 on any line will disable this option entirely. To whitelist the root UID (0) please enable the OnAccessExcludeRootUID option.<br />"
                           "Also note that if clamd cannot check the uid of the process that generated an on-access scan event (e.g., because OnAccessPrevention was not enabled, and the process already exited), clamd will perform a scan. Thus, setting OnAccessExcludeUID is not guaranteed to prevent every access by the specified uid from triggering a scan (unless OnAccessPrevention is enabled).<br />"
                           "Default: disabled"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessExcludeUID);

    //OnAccessExcludeUname
    cntOnAccessExcludeUname = new StringListWidgetPlug("OnAccessExcludeUname",
                        tr("STRING<br />"
                           "This option allows exclusions via user names when using the on-access scanning client. It can be used multiple times, and has the same potential race condition limitations of the OnAccessExcludeUID option.<br />You may wish to set this the same as the username you set under: Scanning >> User<br />"
                           "Default: disabled"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessExcludeUname);

    //OnAccessMaxFileSize
    cntOnAccessMaxFileSize = new SpinBoxPlug("OnAccessMaxFileSize",
                        tr("SIZE<br />"
                           "Files larger than this value will not be scanned in on access.<br />"
                           "Default: 5M"), 0, 2147483647, 5000000);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessMaxFileSize);

    //OnAccessDisableDDD
    cntOnAccessDisableDDD = new CheckBoxPlug("OnAccessDisableDDD",
                        tr("BOOL<br />"
                           "Disables the dynamic directory determination system which allows for recursively watching include paths.<br />"
                           "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessDisableDDD);

    //OnAccessPrevention
    cntOnAccessPrevention = new CheckBoxPlug("OnAccessPrevention",
                        tr("BOOL<br />"
                           "Enables fanotify blocking when malicious files are found.<br />"
                           "Default: disabled"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessPrevention);

    //OnAccessExtraScanning
    cntOnAccessExtraScanning = new CheckBoxPlug("OnAccessExtraScanning",
                        tr("BOOL<br />"
                           "Toggles extra scanning and notifications when a file or directory is created or moved.<br />"
                           "Requires the DDD system to kick-off extra scans.<br />"
                           "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessExtraScanning);

    //OnAccessCurlTimeout
    cntOnAccessCurlTimeout = new SpinBoxPlug("OnAccessCurlTimeout",
                        tr("NUMBER<br />"
                           "Max amount of time (in milliseconds) that the OnAccess client should spend for every connect, send, and recieve attempt when communicating with clamd via curl.<br />"
                           "Default: 5000 (5 seconds)"), 0, 2147483647, 5);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessCurlTimeout);

    //OnAccessMaxThreads
    cntOnAccessMaxThreads = new SpinBoxPlug("OnAccessMaxThreads",
                        tr("NUMBER<br />"
                           "Max number of scanning threads to allocate to the OnAccess thread pool at startup. These threads are the ones responsible for creating a connection with the daemon and kicking off scanning after an event has been processed. To prevent clamonacc from consuming all clamd's resources keep this lower than clamd's max threads.<br />"
                           "Default: 5"), 0, 2147483647, 5);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessMaxThreads);

    //OnAccessRetryAttempts
    cntOnAccessRetryAttempts = new SpinBoxPlug("OnAccessRetryAttempts",
                        tr("NUMBER<br />"
                           "Number of times the OnAccess client will retry a failed scan due to connection problems (or other issues).<br />"
                           "Default: 0"), 0, 2147483647, 5);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessRetryAttempts);

    //OnAccessDenyOnError
    cntOnAccessDenyOnError = new CheckBoxPlug("OnAccessDenyOnError",
                        tr("BOOL<br />"
                           "When using prevention, if this option is turned on, any errors that occur during scanning will result in the event attempt being denied. This could potentially lead to unwanted system behaviour with certain configurations, so the client defaults this to off and prefers allowing access events in case of scan or connection error.<br />"
                           "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntOnAccessDenyOnError);

    //DisableCertCheck
    cntDisableCertCheck = new CheckBoxPlug("DisableCertCheck",
                        tr("BOOL<br />"
                           "Disable authenticode certificate chain verification in PE files.<br />"
                           "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntDisableCertCheck);

    //ClamAuth
    cntClamAuth = new CheckBoxPlug("ClamAuth",
                        tr("BOOL<br />"
                        "This option enables on-access scanning with ClamAuth on OS X (BETA).<br />"
                        "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamAuth);

    //ClamukoExcludeUID
    cntClamukoExcludeUID = new ListSpinBoxWidgetPlug("ClamukoExcludeUID",
                        tr("NUMBER<br />"
                        "With this option you can whitelist specific UIDs. Processes with these UIDs<br />"
                        "will be able to access all files.<br />"
                        "This option can be used multiple times (one per line).<br />"
                        "Default: 0"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoExcludeUID);

    //ClamukoScannerCount
    cntClamukoScannerCount = new SpinBoxPlug("ClamukoScannerCount",
                        tr("The number of scanner threads that will be started (DazukoFS only).<br />"
                        "Having multiple scanner threads allows Clamuko to serve multiple<br />"
                        "processes simultaneously. This is particularly beneficial on SMP machines.<br />"
                        "Default: 3"), 0, 2147483647, 3);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoScannerCount);

    //ClamukoExcludePath
    cntClamukoExcludePath = new StringListWidgetPlug("ClamukoExcludePath",
                        tr("STRING<br />"
                        "This option allows excluding directories from on-access scanning. It can<br />"
                        "be used multiple times.<br />"
                        "Default: /root"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoExcludePath);

    //ClamukoIncludePath
    cntClamukoIncludePath = new StringListWidgetPlug("ClamukoIncludePath",
                        tr("STRING<br />"
                        "This option specifies a directory (together will all files and directories<br />"
                        "inside this directory) which should be scanned on-access. This option can<br />"
                        "be used multiple times.<br />"
                        "Default: /home"));
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoIncludePath);

    //ClamukoMaxFileSize
    cntClamukoMaxFileSize = new SpinBoxPlug("ClamukoMaxFileSize",
                        tr("SIZE<br />"
                        "Files larger than this value will not be scanned.<br />"
                        "Default: "), 0, 2147483647, 5000000);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoMaxFileSize);

    //ClamukoScanOnAccess
    cntClamukoScanOnAccess = new CheckBoxPlug("ClamukoScanOnAccess",
                        tr("BOOL<br />"
                        "This option enables Clamuko. Dazuko needs to be already configured and<br />"
                        "running.<br />"
                        "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoScanOnAccess);

    //ClamukoScanOnClose
    cntClamukoScanOnClose = new CheckBoxPlug("ClamukoScanOnClose",
                        tr("BOOL<br />"
                        "Scan files when they get closed by the system.<br />"
                        "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoScanOnClose);

    //ClamukoScanOnExec
    cntClamukoScanOnExec = new CheckBoxPlug("ClamukoScanOnExec",
                        tr("BOOL<br />"
                        "Scan files when they get executed by the system.<br />"
                        "Default: yes"), true);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoScanOnExec);

    //ClamukoScanOnOpen
    cntClamukoScanOnOpen = new CheckBoxPlug("ClamukoScanOnOpen",
                        tr("BOOL<br />"
                        "Scan files when they get opened by the system.<br />"
                        "Default: no"), false);
    tabOnAccessScrollAreaWidgetVBox->addWidget(cntClamukoScanOnOpen);

    tabOnAccessScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::clamd_prelude_tab_init(){
    tabPrelude = new QWidget();
    tabWidgetClamd->addTab(tabPrelude, tr("Prelude"));

    QVBoxLayout *tabPreludeVBox = new QVBoxLayout();
    tabPrelude->setLayout(tabPreludeVBox);

    tabPreludeScrollArea = new QScrollArea();
    tabPreludeScrollArea->setWidgetResizable(true);
    tabPreludeVBox->addWidget(tabPreludeScrollArea);

    tabPreludeScrollAreaWidget = new QWidget();
    tabPreludeScrollArea->setWidget(tabPreludeScrollAreaWidget);

    QVBoxLayout *tabPreludeScrollAreaWidgetVBox = new QVBoxLayout();
    tabPreludeScrollAreaWidget->setLayout(tabPreludeScrollAreaWidgetVBox);

    QLabel *plab = new QLabel(
                        "https://www.prelude-siem.org/projects/prelude/wiki<br />"
                        "<br />"
                        "Prelude is a Universal \"Security Information &amp; Event Management\" (SIEM) system. Prelude collects, normalizes, sorts, aggregates, correlates and reports all security-related events independently of the product brand or license giving rise to such events; Prelude is \"agentless\".<br />"
                        "<br />"
                        "As well as being capable of recovering any type of log (system logs, syslog, flat files, etc.), Prelude benefits from a native support with a number of systems dedicated to enriching information even further (snort, samhain, ossec, auditd, etc.).<br />"
                        "<br />");
    plab->setWordWrap(true);
    tabPreludeScrollAreaWidgetVBox->addWidget(plab);

    //PreludeEnable
    cntPreludeEnable = new CheckBoxPlug("PreludeEnable",
                        tr(""), false);
    tabPreludeScrollAreaWidgetVBox->addWidget(cntPreludeEnable);

    //PreludeAnalyzerName
    cntPreludeAnalyzerName = new LineEditPlug("PreludeAnalyzerName",
                        tr(""), "");
    cntPreludeAnalyzerName->getEckbox()->hide();
    tabPreludeScrollAreaWidgetVBox->addWidget(cntPreludeAnalyzerName);
    connect(cntPreludeEnable->getEckbox(), &QCheckBox::stateChanged, [=](int state) {
        cntPreludeAnalyzerName->getLabel()->setEnabled(state);
        cntPreludeAnalyzerName->getLineEdit()->setEnabled(state);
    });

    tabPreludeScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::freshclam_tab_init(){
    QVBoxLayout *pageFreshclamVBox = new QVBoxLayout();
    pageFreshclam->setLayout(pageFreshclamVBox);

    tabWidgetFreshclam = new QTabWidget();
    pageFreshclamVBox->addWidget(tabWidgetFreshclam);
}

void ConfigureDialog::freshclam_logs_tab_init(){
    tabFreshLogs = new QWidget();
    tabWidgetFreshclam->addTab(tabFreshLogs, tr("Logs"));

    QVBoxLayout *tabFreshLogsVBox = new QVBoxLayout();
    tabFreshLogs->setLayout(tabFreshLogsVBox);

    tabFreshLogsScrollArea = new QScrollArea();
    tabFreshLogsScrollArea->setWidgetResizable(true);
    tabFreshLogsVBox->addWidget(tabFreshLogsScrollArea);

    tabFreshLogsScrollAreaWidget = new QWidget();
    tabFreshLogsScrollArea->setWidget(tabFreshLogsScrollAreaWidget);

    QVBoxLayout *tabFreshLogsScrollAreaWidgetVBox = new QVBoxLayout();
    tabFreshLogsScrollAreaWidget->setLayout(tabFreshLogsScrollAreaWidgetVBox);

    //FreshLogFileMaxSize
    cntFreshLogFileMaxSize = new SpinBoxPlug("LogFileMaxSize",
                        tr("SIZE<br />"
                           "Limit the size of the log file. The logger will be automatically disabled if the file is greater than SIZE. Value of 0 disables the limit.<br />"
                           "Default: 1M"), 0, 2147483647, 0);
    tabFreshLogsScrollAreaWidgetVBox->addWidget(cntFreshLogFileMaxSize);

    //FreshLogTime
    cntFreshLogTime = new CheckBoxPlug("LogTime",
                        tr("BOOL<br />"
                           "Log time with each message.<br />"
                           "Default: no"), false);
    tabFreshLogsScrollAreaWidgetVBox->addWidget(cntFreshLogTime);

    //FreshLogSyslog
    cntFreshLogSyslog = new CheckBoxPlug("LogSyslog",
                        tr("BOOL<br />"
                           "Enable logging to Syslog. May be used in combination with UpdateLogFile.<br />"
                           "Default: disabled."), false);
    tabFreshLogsScrollAreaWidgetVBox->addWidget(cntFreshLogSyslog);

    //FreshLogFacility
    cntFreshLogFacility = new LineEditPlug("LogFacility",
                        tr("STRING<br />"
                           "Specify the type of syslog messages - please refer to 'man syslog' for facility names.<br />"
                           "Default: LOG_LOCAL6"), "");
    tabFreshLogsScrollAreaWidgetVBox->addWidget(cntFreshLogFacility);

    //FreshLogVerbose
    cntFreshLogVerbose = new CheckBoxPlug("LogVerbose",
                        tr("BOOL<br />"
                           "Enable verbose logging.<br />"
                           "Default: disabled"), false);
    tabFreshLogsScrollAreaWidgetVBox->addWidget(cntFreshLogVerbose);

    //FreshLogRotate
    cntFreshLogRotate = new CheckBoxPlug("LogRotate",
                        tr("BOOL<br />"
                           "Rotate log file. Requires LogFileMaxSize option set prior to this option.<br />"
                           "Default: no"), false);
    tabFreshLogsScrollAreaWidgetVBox->addWidget(cntFreshLogRotate);

    tabFreshLogsScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::freshclam_connect_tab_init(){
    tabFreshConnect = new QWidget();
    tabWidgetFreshclam->addTab(tabFreshConnect, tr("Connect"));

    QVBoxLayout *tabFreshConnectVBox = new QVBoxLayout();
    tabFreshConnect->setLayout(tabFreshConnectVBox);

    tabFreshConnectScrollArea = new QScrollArea();
    tabFreshConnectScrollArea->setWidgetResizable(true);
    tabFreshConnectVBox->addWidget(tabFreshConnectScrollArea);

    tabFreshConnectScrollAreaWidget = new QWidget();
    tabFreshConnectScrollArea->setWidget(tabFreshConnectScrollAreaWidget);

    QVBoxLayout *tabFreshConnectScrollAreaWidgetVBox = new QVBoxLayout();
    tabFreshConnectScrollAreaWidget->setLayout(tabFreshConnectScrollAreaWidgetVBox);

    //FreshPidFile
    cntFreshPidFile = new LineEditPlug("PidFile",
                        tr("STRING<br />"
                           "This option allows you to save the process identifier of the daemon to a file specified in the argument.<br />"
                           "Default: disabled"), "");
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshPidFile);

    //FreshDatabaseDirectory
    cntFreshDatabaseDirectory = new LineEditPlug("DatabaseDirectory",
                        tr("STRING<br />"
                           "Path to a directory containing database files.<br />"
                           "Default: /var/lib/clamav"), "");
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshDatabaseDirectory);

    //FreshForeground
    cntFreshForeground = new CheckBoxPlug("Foreground",
                        tr("BOOL<br />"
                           "Don't fork into background.<br />"
                           "Default: no"), false);
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshForeground);

    //FreshDebug
    cntFreshDebug = new CheckBoxPlug("Debug",
                        tr("BOOL<br />"
                           "Enable debug messages in libclamav.<br />"
                           "Default: no"), false);
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshDebug);

    //FreshUpdateLogFile
    cntFreshUpdateLogFile = new LineEditPlug("UpdateLogFile",
                        tr("STRING<br />"
                           "Enable logging to a specified file. Highly recommended.<br />"
                           "Default: disabled."), "");
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshUpdateLogFile);

    //FreshDatabaseOwner
    cntFreshDatabaseOwner = new LineEditPlug("DatabaseOwner",
                        tr("STRING<br />"
                           "When started by root, drop privileges to a specified user.<br />"
                           "Default:"), "");
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshDatabaseOwner);

    //FreshChecks
    cntFreshChecks = new SpinBoxPlug("Checks",
                    tr("NUMBER<br />"
                       "Number of database checks per day.<br />"
                       "Default: 12"), 0, 2147483647, 0);
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshChecks);

    //FreshDNSDatabaseInfo
    cntFreshDNSDatabaseInfo = new LineEditPlug("DNSDatabaseInfo",
                        tr("STRING<br />"
                           "Use DNS to verify the virus database version. FreshClam uses DNS TXT records<br />"
                           "to verify the versions of the database and software itself. With this<br />"
                           "directive you can change the database verification domain.<br />"
                           "WARNING: Please don't change it unless you're configuring freshclam to use<br />"
                           "your own database verification domain."
                           "Default: enabled, pointing to current.cvd.clamav.net"), "current.cvd.clamav.net");
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshDNSDatabaseInfo);

    //FreshDatabaseMirror
    cntFreshDatabaseMirror = new StringListWidgetPlug("DatabaseMirror",
                        tr("STRING<br />"
                           "DatabaseMirror specifies to which mirror(s) freshclam should connect. You should have at least one entries: database.clamav.net. Now that CloudFlare is being used as our Content Delivery Network (CDN), this one domain name works world-wide to direct freshclam to the closest geographic endpoint.<br />"
                           "Default: database.clamav.net"));
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshDatabaseMirror);

    //FreshPrivateMirror
    cntFreshPrivateMirror = new StringListWidgetPlug("PrivateMirror",
                        tr("STRING<br />"
                           "This option allows you to easily point freshclam to private mirrors. If PrivateMirror is set, freshclam does not attempt to use DNS to determine whether its databases are out-of-date, instead it will use the If-Modified-Since request or directly check the headers of the remote database files. For each database, freshclam first attempts to download the CLD file. If that fails, it tries to download the CVD file. This option overrides DatabaseMirror, DNSDatabaseInfo and ScriptedUpdates. It can be used multiple times to provide fall-back mirrors.<br />"
                           "Default: disabled"));
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshPrivateMirror);

    //FreshMaxAttempts
    cntFreshMaxAttempts = new SpinBoxPlug("MaxAttempts",
                    tr("NUMBER<br />"
                       "How many attempts (per mirror) to make before giving up.<br />"
                       "Default: 3 (per mirror)"), 0, 2147483647, 0);
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshMaxAttempts);

    //FreshScriptedUpdates
    cntFreshScriptedUpdates = new CheckBoxPlug("ScriptedUpdates",
                    tr("BOOL<br />"
                       "With this option you can control scripted updates. It's highly recommended to keep it enabled.<br />"
                       "Default: yes"), false);
    tabFreshConnectScrollAreaWidgetVBox->addWidget(cntFreshScriptedUpdates);

    tabFreshConnectScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::freshclam_databases_tab_init(){
    tabFreshDatabases = new QWidget();
    tabWidgetFreshclam->addTab(tabFreshDatabases, tr("Databases"));

    QVBoxLayout *tabFreshDatabasesVBox = new QVBoxLayout();
    tabFreshDatabases->setLayout(tabFreshDatabasesVBox);

    tabFreshDatabasesScrollArea = new QScrollArea();
    tabFreshDatabasesScrollArea->setWidgetResizable(true);
    tabFreshDatabasesVBox->addWidget(tabFreshDatabasesScrollArea);

    tabFreshDatabasesScrollAreaWidget = new QWidget();
    tabFreshDatabasesScrollArea->setWidget(tabFreshDatabasesScrollAreaWidget);

    QVBoxLayout *tabFreshDatabasesScrollAreaWidgetVBox = new QVBoxLayout();
    tabFreshDatabasesScrollAreaWidget->setLayout(tabFreshDatabasesScrollAreaWidgetVBox);

    //FreshTestDatabases
    cntFreshTestDatabases = new CheckBoxPlug("TestDatabases",
                        tr("BOOL<br />"
                           "With this option enabled, freshclam will attempt to load new<br />"
                           "databases into memory to make sure they are properly handled<br />"
                           "by libclamav before replacing the old ones. Tip: This feature uses a lot of RAM. If your system has limited RAM and you are actively running ClamD or ClamScan during the update, then you may need to set `TestDatabases no`."
                           "Default: enabled"), true);
    tabFreshDatabasesScrollAreaWidgetVBox->addWidget(cntFreshTestDatabases);

    //FreshCompressLocalDatabase
    cntFreshCompressLocalDatabase = new CheckBoxPlug("CompressLocalDatabase",
                        tr("BOOL<br />"
                           "By default freshclam will keep the local databases (.cld) uncompressed to make their handling faster. With this option you can enable the compression; the change will take effect with the next database update.<br />"
                           "Default: no"), false);
    tabFreshDatabasesScrollAreaWidgetVBox->addWidget(cntFreshCompressLocalDatabase);

    //FreshExtraDatabase
    cntFreshExtraDatabase = new StringListWidgetPlug("ExtraDatabase",
                        tr("STRING<br />"
                           "Download an additional 3rd party signature database distributed through the ClamAV mirrors. This option can be used multiple times.<br />"
                           "Default: disabled"));
    tabFreshDatabasesScrollAreaWidgetVBox->addWidget(cntFreshExtraDatabase);

    //FreshExcludeDatabase
    cntFreshExcludeDatabase = new StringListWidgetPlug("ExcludeDatabase",
                        tr("STRING<br />"
                           "Exclude a standard signature database (opt-out). This option can be used multiple times.<br />"
                           "Default: disabled"));
    tabFreshDatabasesScrollAreaWidgetVBox->addWidget(cntFreshExcludeDatabase);

    //FreshDatabaseCustomURL
    cntFreshDatabaseCustomURL = new StringListWidgetPlug("DatabaseCustomURL",
                        tr("STRING<br />"
                           "With this option you can provide custom sources for database files. This option can be used multiple times. Support for: http(s)://, ftp(s)://, or file:// Example usage: DatabaseCustomURL https://myserver.com:4567/whitelist.wdb<br />"
                           "Default: disabled"));
    tabFreshDatabasesScrollAreaWidgetVBox->addWidget(cntFreshDatabaseCustomURL);

    tabFreshDatabasesScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::freshclam_http_tab_init(){
    tabFreshHTTP = new QWidget();
    tabWidgetFreshclam->addTab(tabFreshHTTP, tr("HTTP"));

    QVBoxLayout *tabFreshHTTPVBox = new QVBoxLayout();
    tabFreshHTTP->setLayout(tabFreshHTTPVBox);

    tabFreshHTTPScrollArea = new QScrollArea();
    tabFreshHTTPScrollArea->setWidgetResizable(true);
    tabFreshHTTPVBox->addWidget(tabFreshHTTPScrollArea);

    tabFreshHTTPScrollAreaWidget = new QWidget();
    tabFreshHTTPScrollArea->setWidget(tabFreshHTTPScrollAreaWidget);

    QVBoxLayout *tabFreshHTTPScrollAreaWidgetVBox = new QVBoxLayout();
    tabFreshHTTPScrollAreaWidget->setLayout(tabFreshHTTPScrollAreaWidgetVBox);

    //FreshHTTPProxyServer
    cntFreshHTTPProxyServer = new LineEditPlug("HTTPProxyServer",
                        tr("STRING<br />"
                           "Use given proxy server for database downloads. May be prefixed with [scheme]:// to specify which kind of proxy is used. http:// HTTP Proxy. Default when no scheme or proxy type is specified. https:// HTTPS Proxy. (Added in 7.52.0 for OpenSSL, GnuTLS and NSS) socks4:// SOCKS4 Proxy. socks4a:// SOCKS4a Proxy. Proxy resolves URL hostname. socks5:// SOCKS5 Proxy. socks5h:// SOCKS5 Proxy. Proxy resolves URL hostname.<br />"
                           "Default: disabled"), "");
    tabFreshHTTPScrollAreaWidgetVBox->addWidget(cntFreshHTTPProxyServer);

    //FreshHTTPProxyPort
    cntFreshHTTPProxyPort = new SpinBoxPlug("HTTPProxyPort",
                        tr("NUMBER<br />"
                           "Use given TCP port for database downloads.<br />"
                           "Default: disabled"), 0, 2147483647, 0);
    tabFreshHTTPScrollAreaWidgetVBox->addWidget(cntFreshHTTPProxyPort);

    //FreshHTTPProxyUsername
    cntFreshHTTPProxyUsername = new LineEditPlug("HTTPProxyUsername",
                        tr("STRING<br />"
                           "Proxy usage is authenticated through given username.<br />"
                           "Default: disabled"), "");
    tabFreshHTTPScrollAreaWidgetVBox->addWidget(cntFreshHTTPProxyUsername);

    //FreshHTTPProxyPassword
    cntFreshHTTPProxyPassword = new LineEditPlug("HTTPProxyPassword",
                        tr("STRING<br />"
                           "Proxy usage is authenticated through given password.<br />"
                           "Default: disabled"), "");
    tabFreshHTTPScrollAreaWidgetVBox->addWidget(cntFreshHTTPProxyPassword);

    //FreshHTTPUserAgent
    cntFreshHTTPUserAgent = new LineEditPlug("HTTPUserAgent",
                        tr("STRING<br />"
                           "If your servers are behind a firewall/proxy which applies User-Agent filtering, you can use this option to force the use of a different User-Agent header.<br />"
                           "Default: clamav/version_number"), "");
    tabFreshHTTPScrollAreaWidgetVBox->addWidget(cntFreshHTTPUserAgent);

    tabFreshHTTPScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::freshclam_misc_tab_init(){
    tabFreshMisc = new QWidget();
    tabWidgetFreshclam->addTab(tabFreshMisc, tr("Misc"));

    QVBoxLayout *tabFreshMiscVBox = new QVBoxLayout();
    tabFreshMisc->setLayout(tabFreshMiscVBox);

    tabFreshMiscScrollArea = new QScrollArea();
    tabFreshMiscScrollArea->setWidgetResizable(true);
    tabFreshMiscVBox->addWidget(tabFreshMiscScrollArea);

    tabFreshMiscScrollAreaWidget = new QWidget();
    tabFreshMiscScrollArea->setWidget(tabFreshMiscScrollAreaWidget);

    QVBoxLayout *tabFreshMiscScrollAreaWidgetVBox = new QVBoxLayout();
    tabFreshMiscScrollAreaWidget->setLayout(tabFreshMiscScrollAreaWidgetVBox);

    //FreshNotifyClamd
    cntFreshNotifyClamd = new LineEditPlug("NotifyClamd",
                        tr("STRING<br />"
                           "Notify a running clamd(8) to reload its database after a download has occurred. The path for clamd.conf file must be provided.<br />"
                           "Default: The default is to not notify clamd. See clamd.conf(5)'s option SelfCheck for how clamd(8) handles database updates in this case."), "");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshNotifyClamd);

    //FreshOnUpdateExecute
    cntFreshOnUpdateExecute = new LineEditPlug("OnUpdateExecute",
                        tr("STRING<br />"
                           "Run a command after a successful database update. Use EXIT_1 to return 1 after successful database update.<br />"
                           "Default: disabled"), "");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshOnUpdateExecute);

    //FreshOnErrorExecute
    cntFreshOnErrorExecute = new LineEditPlug("OnErrorExecute",
                        tr("STRING<br />"
                           "Execute this command after a database update has failed.<br />"
                           "Default: disabled"), "");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshOnErrorExecute);

    //FreshOnOutdatedExecute
    cntFreshOnOutdatedExecute = new LineEditPlug("OnOutdatedExecute",
                        tr("STRING<br />"
                           "Execute this command when freshclam reports outdated version. In the command string %v will be replaced by the new version number.<br />"
                           "Default: disabled"), "");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshOnOutdatedExecute);

    //FreshLocalIPAddress
    cntFreshLocalIPAddress = new LineEditPlug("LocalIPAddress",
                        tr("STRING<br />"
                           "Use IP as client address for downloading databases. Useful for multi homed systems.<br />"
                           "Default: Use OS'es default outgoing IP address."), "");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshLocalIPAddress);

    //FreshConnectTimeout
    cntFreshConnectTimeout = new SpinBoxPlug("ConnectTimeout",
                        tr("NUMBER<br />"
                           "Timeout in seconds when connecting to database server.<br />"
                           "Default: 10"), 0, 2147483647, 0);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshConnectTimeout);

    //FreshReceiveTimeout
    cntFreshReceiveTimeout = new SpinBoxPlug("ReceiveTimeout",
                        tr("NUMBER<br />"
                           "Timeout in seconds when reading from database server. 0 means no timeout.<br />"
                           "Default: 0"), 0, 2147483647, 0);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshReceiveTimeout);

    //FreshSafeBrowsing
    cntFreshSafeBrowsing = new CheckBoxPlug("SafeBrowsing",
                        tr("BOOL<br />"
                           "Deprecated option to download signatures derived from the Google Safe Browsing API. See https://blog.clamav.net/2020/06/the-future-of-clamav-safebrowsing.html for more details."
                           "Default: no"), false);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshSafeBrowsing);

    //FreshBytecode
    cntFreshBytecode = new CheckBoxPlug("Bytecode",
                        tr("BOOL<br />"
                           "This option enables downloading of bytecode.cvd, which includes additional<br />"
                           " detection mechanisms and improvements to the ClamAV engine.<br />"
                           "Default: yes"), true);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshBytecode);

    //FreshAllowSupplementaryGroups
    cntFreshAllowSupplementaryGroups = new CheckBoxPlug("AllowSupplementaryGroups",
                        tr("BOOL<br />"
                        "Initialize a supplementary group access (the process must be started by root).<br />"
                        "Default: no"), false);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshAllowSupplementaryGroups);

    //FreshDetectionStatsCountry
    cntFreshDetectionStatsCountry = new LineEditPlug("DetectionStatsCountry",
                        tr("STRING<br />"
                        "Country of origin of malware/detection statistics (for statistical<br />"
                        "purposes only). The statistics collector at ClamAV.net will look up<br />"
                        "your IP address to determine the geographical origin of the malware<br />"
                        "reported by your installation. If this installation is mainly used to<br />"
                        "scan data which comes from a different location, please enable this<br />"
                        "option and enter a two-letter code (see http://www.iana.org/domains/root/db/)<br />"
                        "of the country of origin.<br />"
                        "Default: country-code"), "country-code");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshDetectionStatsCountry);

    //FreshSubmitDetectionStats
    cntFreshSubmitDetectionStats = new LineEditPlug("SubmitDetectionStats",
                        tr("STRING<br />"
                        "When enabled freshclam will submit statistics to the ClamAV Project about<br />"
                        "the latest virus detections in your environment. The ClamAV maintainers<br />"
                        "will then use this data to determine what types of malware are the most<br />"
                        "detected in the field and in what geographic area they are.<br />"
                        "Freshclam will connect to clamd in order to get recent statistics.<br />"
                        "Default: /path/to/clamd.conf"), "/etc/clamd.conf");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshSubmitDetectionStats);

    //FreshDetectionStatsHostID
    cntFreshDetectionStatsHostID = new LineEditPlug("DetectionStatsHostID",
                        tr("STRING<br />"
                        "This option enables support for our \"Personal Statistics\" service.<br />"
                        "When this option is enabled, the information on malware detected by<br />"
                        "your clamd installation is made available to you through our website.<br />"
                        "To get your HostID, log on http://www.stats.clamav.net and add a new<br />"
                        "host to your host list. Once you have the HostID, uncomment this option<br />"
                        "and paste the HostID here. As soon as your freshclam starts submitting<br />"
                        "information to our stats collecting service, you will be able to view<br />"
                        "the statistics of this clamd installation by logging into<br />"
                        "http://www.stats.clamav.net with the same credentials you used to<br />"
                        "generate the HostID. For more information refer to:<br />"
                        "http://www.clamav.net/doc/cctts.html<br />"
                        "This feature requires SubmitDetectionStats to be enabled.<br />"
                        "Default: unique-id"), "unique-id");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshDetectionStatsHostID);

    //FreshStatsEnabled
    cntFreshStatsEnabled = new CheckBoxPlug("StatsEnabled",
                        tr("BOOL<br />"
                        "Enable submission of statistical data.<br />"
                        "Default: yes"), true);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshStatsEnabled);

    //FreshStatsHostID
    cntFreshStatsHostID = new LineEditPlug("StatsHostID",
                        tr("STRING<br />"
                        "HostID in the form of an UUID to use when submitting statistical<br />"
                        "information. See the clamscan manpage for more information.<br />"
                        "Default: default"), "default");
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshStatsHostID);

    //FreshStatsTimeout
    cntFreshStatsTimeout = new SpinBoxPlug("StatsTimeout",
                        tr("NUMBER<br />"
                        "Timeout in seconds to timeout communication with the stats server.<br />"
                        "Default: 10"), 0, 2147483647, 10);
    tabFreshMiscScrollAreaWidgetVBox->addWidget(cntFreshStatsTimeout);

    tabFreshMiscScrollAreaWidgetVBox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Fixed, QSizePolicy::Expanding));
}

void ConfigureDialog::snort_tab_init(){
    QVBoxLayout *pageSnortVBox = new QVBoxLayout();
    pageSnort->setLayout(pageSnortVBox);

    tabWidgetSnort = new QTabWidget();
    pageSnortVBox->addWidget(tabWidgetSnort);
}

void ConfigureDialog::snort_support_tab_init(){
    tabSnortSupport = new QWidget();
    tabWidgetSnort->addTab(tabSnortSupport, tr("Support"));

    QVBoxLayout *tabSnortSupportVBox = new QVBoxLayout();
    tabSnortSupport->setLayout(tabSnortSupportVBox);

    tabSnortSupportScrollArea = new QScrollArea();
    tabSnortSupportScrollArea->setWidgetResizable(true);
    tabSnortSupportVBox->addWidget(tabSnortSupportScrollArea);

    tabSnortSupportScrollAreaWidget = new QWidget();
    tabSnortSupportScrollArea->setWidget(tabSnortSupportScrollAreaWidget);

    QVBoxLayout *tabSnortSupportScrollAreaWidgetVBox = new QVBoxLayout();
    tabSnortSupportScrollAreaWidget->setLayout(tabSnortSupportScrollAreaWidgetVBox);

    //Location of Snort Rules
    cntLocationOfSnortRules = new FileDialogPlug("Location of snort rules",
                        tr("STRING<br />"
                        "Location in the filesystem for the rules directory, including the etc/snort.conf file<br />"
                        "Default: /etc/snort"), "", "", QFileDialog::ShowDirsOnly);
    tabSnortSupportScrollAreaWidgetVBox->addWidget(cntLocationOfSnortRules);

    //SnortOinkcode
    cntSnortOinkcode = new LineEditPlug("Oinkcode",
                        tr("STRING<br />"
                        "User code to access/update/and download snort rules from snort.org<br />"
                        "Default: "), "");
    tabSnortSupportScrollAreaWidgetVBox->addWidget(cntSnortOinkcode);

    tabSnortSupportScrollAreaWidgetVBox->addStretch();
}

void ConfigureDialog::disableAllClamdconf(){
    //NetSock
    cntLocalSocket->getEckbox()->setChecked(false);
    cntLocalSocketGroup->getEckbox()->setChecked(false);
    cntLocalSocketMode->getEckbox()->setChecked(false);
    cntFixStaleSocket->getEckbox()->setChecked(false);
    cntTCPSocket->getEckbox()->setChecked(false);
    cntTCPAddr->getEckbox()->setChecked(false);
    cntMaxConnectionQueueLength->getEckbox()->setChecked(false);
    cntStreamMaxLength->getEckbox()->setChecked(false);
    cntStreamMinPort->getEckbox()->setChecked(false);
    cntStreamMaxPort->getEckbox()->setChecked(false);
    cntMaxThreads->getEckbox()->setChecked(false);
    cntReadTimeout->getEckbox()->setChecked(false);
    cntCommandReadTimeout->getEckbox()->setChecked(false);
    cntSendBufTimeout->getEckbox()->setChecked(false);
    cntMaxQueue->getEckbox()->setChecked(false);
    cntIdleTimeout->getEckbox()->setChecked(false);
    cntExcludePath->getEckbox()->setChecked(false);

    //Logs
    cntLogFile->getEckbox()->setChecked(false);
    cntLogFileUnlock->getEckbox()->setChecked(false);
    cntLogFileMaxSize->getEckbox()->setChecked(false);
    cntLogTime->getEckbox()->setChecked(false);
    cntLogClean->getEckbox()->setChecked(false);
    cntLogSyslog->getEckbox()->setChecked(false);
    cntLogFacility->getEckbox()->setChecked(false);
    cntLogVerbose->getEckbox()->setChecked(false);
    cntLogRotate->getEckbox()->setChecked(false);

    //Parameters
    cntExtendedDetectionInfo->getEckbox()->setChecked(false);
    cntPidFile->getEckbox()->setChecked(false);
    cntTemporaryDirectory->getEckbox()->setChecked(false);
    cntDatabaseDirectory->getEckbox()->setChecked(false);
    cntOfficialDatabaseOnly->getEckbox()->setChecked(false);

    //FileSys
    cntMaxDirectoryRecursion->getEckbox()->setChecked(false);
    cntFollowDirectorySymlinks->getEckbox()->setChecked(false);
    cntFollowFileSymlinks->getEckbox()->setChecked(false);
    cntCrossFilesystems->getEckbox()->setChecked(false);
    cntSelfCheck->getEckbox()->setChecked(false);
    cntDisableCache->getEckbox()->setChecked(false);
    cntVirusEvent->getEckbox()->setChecked(false);
    cntExitOnOOM->getEckbox()->setChecked(false);
    cntAllowAllMatchScan->getEckbox()->setChecked(false);
    cntForeground->getEckbox()->setChecked(false);
    cntDebug->getEckbox()->setChecked(false);
    cntLeaveTemporaryFiles->getEckbox()->setChecked(false);

    //Scanning
    cntUser->getEckbox()->setChecked(false);
    cntAllowSupplementaryGroups->getEckbox()->setChecked(false);
    cntMailFollowURLs->getEckbox()->setChecked(false);
    cntBytecode->getEckbox()->setChecked(false);
    cntBytecodeSecurity->getEckbox()->setChecked(false);
    cntBytecodeTimeout->getEckbox()->setChecked(false);
    cntBytecodeUnsigned->getEckbox()->setChecked(false);
    cntBytecodeMode->getEckbox()->setChecked(false);
    cntDetectPUA->getEckbox()->setChecked(false);
    cntExcludePUA->getEckbox()->setChecked(false);
    cntIncludePUA->getEckbox()->setChecked(false);
    cntScanPE->getEckbox()->setChecked(false);
    cntScanELF->getEckbox()->setChecked(false);
    cntScanMail->getEckbox()->setChecked(false);
    cntScanPartialMessages->getEckbox()->setChecked(false);
    cntPhishingSignatures->getEckbox()->setChecked(false);
    cntPhishingScanURLs->getEckbox()->setChecked(false);
    cntHeuristicAlerts->getEckbox()->setChecked(false);
    cntHeuristicScanPrecedence->getEckbox()->setChecked(false);
    cntStructuredDataDetection->getEckbox()->setChecked(false);
    cntStructuredMinCreditCardCount->getEckbox()->setChecked(false);
    cntStructuredMinSSNCount->getEckbox()->setChecked(false);
    cntStructuredSSNFormatNormal->getEckbox()->setChecked(false);
    cntStructuredSSNFormatStripped->getEckbox()->setChecked(false);
    cntScanHTML->getEckbox()->setChecked(false);
    cntScanOLE2->getEckbox()->setChecked(false);
    cntScanPDF->getEckbox()->setChecked(false);
    cntScanSWF->getEckbox()->setChecked(false);
    cntScanXMLDOCS->getEckbox()->setChecked(false);
    cntScanHWP3->getEckbox()->setChecked(false);
    cntScanArchive->getEckbox()->setChecked(false);

    //Alerts
    cntAlertBrokenExecutables->getEckbox()->setChecked(false);
    cntAlertEncrypted->getEckbox()->setChecked(false);
    cntAlertEncryptedArchive->getEckbox()->setChecked(false);
    cntAlertEncryptedDoc->getEckbox()->setChecked(false);
    cntAlertOLE2Macros->getEckbox()->setChecked(false);
    cntAlertExceedsMax->getEckbox()->setChecked(false);
    cntAlertPhishingSSLMismatch->getEckbox()->setChecked(false);
    cntAlertPhishingCloak->getEckbox()->setChecked(false);
    cntAlertPartitionIntersection->getEckbox()->setChecked(false);
    cntForceToDisk->getEckbox()->setChecked(false);
    cntMaxScanTime->getEckbox()->setChecked(false);
    cntMaxScanSize->getEckbox()->setChecked(false);
    cntMaxFileSize->getEckbox()->setChecked(false);
    cntMaxRecursion->getEckbox()->setChecked(false);
    cntMaxFiles->getEckbox()->setChecked(false);
    cntMaxEmbeddedPE->getEckbox()->setChecked(false);
    cntMaxHTMLNormalize->getEckbox()->setChecked(false);
    cntMaxHTMLNoTags->getEckbox()->setChecked(false);
    cntMaxScriptNormalize->getEckbox()->setChecked(false);
    cntMaxZipTypeRcg->getEckbox()->setChecked(false);
    cntMaxPartitions->getEckbox()->setChecked(false);
    cntMaxIconsPE->getEckbox()->setChecked(false);
    cntMaxRecHWP3->getEckbox()->setChecked(false);
    cntPCREMatchLimit->getEckbox()->setChecked(false);
    cntPCRERecMatchLimit->getEckbox()->setChecked(false);
    cntPCREMaxFileSize->getEckbox()->setChecked(false);

    //OnAccess
    cntScanOnAccess->getEckbox()->setChecked(false);
    cntOnAccessMountPath->getEckbox()->setChecked(false);
    cntOnAccessIncludePath->getEckbox()->setChecked(false);
    cntOnAccessExcludePath->getEckbox()->setChecked(false);
    cntOnAccessExcludeRootUID->getEckbox()->setChecked(false);
    cntOnAccessExcludeUID->getEckbox()->setChecked(false);
    cntOnAccessExcludeUname->getEckbox()->setChecked(false);
    cntOnAccessMaxFileSize->getEckbox()->setChecked(false);
    cntOnAccessDisableDDD->getEckbox()->setChecked(false);
    cntOnAccessPrevention->getEckbox()->setChecked(false);
    cntOnAccessExtraScanning->getEckbox()->setChecked(false);
    cntOnAccessCurlTimeout->getEckbox()->setChecked(false);
    cntOnAccessMaxThreads->getEckbox()->setChecked(false);
    cntOnAccessRetryAttempts->getEckbox()->setChecked(false);
    cntOnAccessDenyOnError->getEckbox()->setChecked(false);
    cntDisableCertCheck->getEckbox()->setChecked(false);
    cntClamAuth->getEckbox()->setChecked(false);
    cntClamukoExcludePath->getEckbox()->setChecked(false);
    cntClamukoExcludeUID->getEckbox()->setChecked(false);
    cntClamukoScannerCount->getEckbox()->setChecked(false);

    //Prelude
    cntPreludeEnable->getEckbox()->setChecked(false);
    cntPreludeAnalyzerName->getEckbox()->setChecked(false);}

void ConfigureDialog::disableAllFreshclamconf(){
    //FreshLogs
    cntFreshLogFileMaxSize->getEckbox()->setChecked(false);
    cntFreshLogTime->getEckbox()->setChecked(false);
    cntFreshLogSyslog->getEckbox()->setChecked(false);
    cntFreshLogFacility->getEckbox()->setChecked(false);
    cntFreshLogVerbose->getEckbox()->setChecked(false);
    cntFreshLogRotate->getEckbox()->setChecked(false);

    //FreshConnect
    cntFreshPidFile->getEckbox()->setChecked(false);
    cntFreshDatabaseDirectory->getEckbox()->setChecked(false);
    cntFreshForeground->getEckbox()->setChecked(false);
    cntFreshDebug->getEckbox()->setChecked(false);
    cntFreshUpdateLogFile->getEckbox()->setChecked(false);
    cntFreshDatabaseOwner->getEckbox()->setChecked(false);
    cntFreshChecks->getEckbox()->setChecked(false);
    cntFreshDNSDatabaseInfo->getEckbox()->setChecked(false);
    cntFreshDatabaseMirror->getEckbox()->setChecked(false);
    cntFreshPrivateMirror->getEckbox()->setChecked(false);
    cntFreshMaxAttempts->getEckbox()->setChecked(false);
    cntFreshScriptedUpdates->getEckbox()->setChecked(false);

    //FreshDatabases
    cntFreshTestDatabases->getEckbox()->setChecked(false);
    cntFreshCompressLocalDatabase->getEckbox()->setChecked(false);
    cntFreshExtraDatabase->getEckbox()->setChecked(false);
    cntFreshExcludeDatabase->getEckbox()->setChecked(false);
    cntFreshDatabaseCustomURL->getEckbox()->setChecked(false);

    //FreshHTTP
    cntFreshHTTPProxyServer->getEckbox()->setChecked(false);
    cntFreshHTTPProxyPort->getEckbox()->setChecked(false);
    cntFreshHTTPProxyUsername->getEckbox()->setChecked(false);
    cntFreshHTTPProxyPassword->getEckbox()->setChecked(false);
    cntFreshHTTPUserAgent->getEckbox()->setChecked(false);

    //FreshMisc
    cntFreshNotifyClamd->getEckbox()->setChecked(false);
    cntFreshOnUpdateExecute->getEckbox()->setChecked(false);
    cntFreshOnErrorExecute->getEckbox()->setChecked(false);
    cntFreshOnOutdatedExecute->getEckbox()->setChecked(false);
    cntFreshLocalIPAddress->getEckbox()->setChecked(false);
    cntFreshConnectTimeout->getEckbox()->setChecked(false);
    cntFreshReceiveTimeout->getEckbox()->setChecked(false);
    cntFreshSafeBrowsing->getEckbox()->setChecked(false);
    cntFreshBytecode->getEckbox()->setChecked(false);

}

void ConfigureDialog::disableAllSnort(){

}

bool ConfigureDialog::matchBoolTrue(QRegularExpression r, QByteArray l){
    return r.match(l).captured("varname").toLower() == QString("true") ||
            r.match(l).captured("varname").toLower() == QString("yes");
}

bool ConfigureDialog::matchBoolFalse(QRegularExpression r, QByteArray l){
    return r.match(l).captured("varname").toLower() == QString("false") ||
            r.match(l).captured("varname").toLower() == QString("no");
}

bool ConfigureDialog::parseBoolUi(QString part, QByteArray l, QCheckBox *cbEnable, QCheckBox *cb){
    Q_UNUSED(part)
    Q_UNUSED(l)
    Q_UNUSED(cbEnable)
    Q_UNUSED(cb)
    return false;
}

void ConfigureDialog::listen_pushButtonOk_clicked(){
    listen_pushButtonApply_clicked();
    listen_pushButtonCancel_clicked();
}

void ConfigureDialog::listen_pushButtonReloadClamAV_clicked(){
    disableAllFreshclamconf();
}

void ConfigureDialog::listen_pushButtonCancel_clicked(){
    lineEditLocationOfClamdconf->setText("");
    lineEditLocationOfFreshclamconf->setText("");
    cntLocationOfSnortRules->getLineEdit()->setText("");
    spinBoxEntriesPerPage->setValue(40);
    checkBoxMonitorOnAccess->setChecked(false);
    checkBoxEnableClamOneQuarantine->setChecked(false);
    checkBoxEnableClamOneSnort->setChecked(false);
    tabWidgetClamd->setCurrentIndex(0);
    tabWidgetFreshclam->setCurrentIndex(0);
    listWidgetMain->setCurrentRow(0);
    oldClamdconf = QByteArray();
    oldErrClamdconf = QByteArray();
    oldFreshclamconf = QByteArray();
    oldErrFreshclamconf = QByteArray();
    hide();
}

void ConfigureDialog::listen_pushButtonApply_clicked(){
    bool sendReload = false;
    Q_UNUSED(sendReload)
    emit setValDB("clamdconf", lineEditLocationOfClamdconf->text());
    emit setValDB("freshclamconf", lineEditLocationOfFreshclamconf->text());
    emit setValDB("entriesperpage", QString::number(spinBoxEntriesPerPage->value()));
    emit setValDB("monitoronaccess", (checkBoxMonitorOnAccess->isChecked())?"yes":"no");
    emit setValDB("enablequarantine", (checkBoxEnableClamOneQuarantine->isChecked())?"yes":"no");
    emit setValDB("enablesnort", (checkBoxEnableClamOneSnort->isChecked())?"yes":"no");
    emit setValDB("maxquarantinesize", QString::number(spinBoxMaximumFileSizeToQuarantine->value()));
    emit setValDB("quarantinefilesdirectory", lineEditLocationOfQuarantineFilesDirectory->text());
    emit setValDB("snortconf", (cntLocationOfSnortRules->getEckbox()->isChecked())?cntLocationOfSnortRules->getLineEdit()->text():"");
    emit setValDB("oinkcode", (cntSnortOinkcode->getEckbox()->isChecked())?cntSnortOinkcode->getLineEdit()->text():"");
    emit refreshEventGeneral(0);
    emit refreshEventFound(0, true);
    emit refreshEventQuarantined(0);
    emit refreshMessages(0);
    emit refreshQuarantineDirectory();
    emit setEnabledQuarantine(checkBoxEnableClamOneQuarantine->isChecked());
    emit setEnabledSnort(checkBoxEnableClamOneSnort->isChecked());
    emit setEnabledMonitorOnAccess(checkBoxMonitorOnAccess->isChecked());
    emit refreshOinkcodeContent();
    QByteArray newClamdconf;
    fileUiToClamdconf(&newClamdconf);
    if(oldClamdconf != newClamdconf){
        //Write new file somehow, needs elivated permissions.
        QFile f(lineEditLocationOfClamdconf->text());
        if(f.open(QFile::WriteOnly|QFile::Truncate)){
            f.write(newClamdconf);
            f.write(oldErrClamdconf);
            f.flush();
            f.close();
            sendReload = true;
        }else{
            QProcess *p = new QProcess();
            p->start("pkexec", QStringList() << "tee" << lineEditLocationOfClamdconf->text());
            if (!p->waitForStarted())
                    return;
            p->write(newClamdconf, newClamdconf.length());
            p->write(oldErrClamdconf, oldErrClamdconf.length());
            p->closeWriteChannel();
            if (!p->waitForFinished())
                    return;
            sendReload = true;
        }
        fileClamdconfToUI(lineEditLocationOfClamdconf->text());
    }
    QByteArray newFreshclamconf;
    fileUiToFreshclamconf(&newFreshclamconf);
    if(oldFreshclamconf != newFreshclamconf){
        //Write new file somehow, needs elivated permissions.
        QFile f(lineEditLocationOfFreshclamconf->text());
        if(f.open(QFile::WriteOnly|QFile::Truncate)){
            f.write(newFreshclamconf);
            f.write(oldErrFreshclamconf);
            f.flush();
            f.close();
            sendReload = true;
        }else{
            QProcess *p = new QProcess();
            p->start("pkexec", QStringList() << "tee" << lineEditLocationOfFreshclamconf->text());
            if (!p->waitForStarted())
                    return;
            p->write(newFreshclamconf, newFreshclamconf.length());
            p->write(oldErrFreshclamconf, oldErrFreshclamconf.length());
            p->closeWriteChannel();
            if (!p->waitForFinished())
                    return;
            sendReload = true;
        }
        fileFreshclamconfToUI(lineEditLocationOfFreshclamconf->text());
    }
    if(sendReload){
        listen_pushButtonReloadClamAV_clicked();
    }
}


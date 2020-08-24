#include "ConfigureDialogCurrent.h"
#include "ui_ConfigureDialogCurrent.h"

ConfigureDialogCurrent::ConfigureDialogCurrent(QString dbLoc, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ConfigureDialogCurrent)
{
    ui->setupUi(this);

    ui->lineEditLocationOfClamonedb->setText(dbLoc);

    ui->stringListExcludePUA->setQStringList(QStringList({"NetTool", "PWTool"}));
    ui->stringListIncludePUA->setQStringList(QStringList({"Spy", "Scanner", "RAT"}));
    ui->stringListTCPAddr->setQStringList(QStringList({"127.0.0.1"}));

    connect(ui->listWidgetMain, &QListWidget::currentRowChanged, ui->stackedWidget, &QStackedWidget::setCurrentIndex);
    connect(ui->lineEditLocationOfClamdconf, &QLineEdit::textChanged, this, &ConfigureDialogCurrent::fileClamdconfToUI);
    connect(ui->lineEditLocationOfFreshclamconf, &QLineEdit::textChanged, this, &ConfigureDialogCurrent::fileFreshclamconfToUI);
}

ConfigureDialogCurrent::~ConfigureDialogCurrent(){
    delete ui;
}

void ConfigureDialogCurrent::updateClamdconfLoc(QString loc){
    ui->lineEditLocationOfClamdconf->setText(loc);
}

void ConfigureDialogCurrent::updateFreshclamconfLoc(QString loc){
    ui->lineEditLocationOfFreshclamconf->setText(loc);
}

void ConfigureDialogCurrent::updateEntriesPerPage(QString loc){
    bool ok;
    qint64 num = loc.toInt(&ok, 10);
    if(!ok || num < 1 || num > 1000000)
        num = 40;
    ui->spinBoxEntriesPerPage->setValue(num);
}

void ConfigureDialogCurrent::updateMonitorOnAccess(bool state){
    ui->checkBoxMonitorOnAccess->setChecked(state);
}

void ConfigureDialogCurrent::updateEnableQuarantine(bool state){
    ui->checkBoxEnableClamOneQuarantine->setChecked(state);
}

void ConfigureDialogCurrent::updateMaximumQuarantineFileSize(quint64 size){
    ui->spinBoxMaximumFileSizeToQuarantine->setValue(size);
}

void ConfigureDialogCurrent::updateLocationQuarantineFileDirectory(QString loc){
    ui->lineEditLocationOfQuarantineFilesDirectory->setText(loc);
}

bool ConfigureDialogCurrent::fileClamdconfToUI(QString filename){
    disableAllClamdconf();
    oldErrClamdconf = QByteArray();
    QFile file(filename);
    if(!file.exists())
        return false;
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    while(!file.atEnd()){
        QRegularExpression re;
        QByteArray line = file.readLine();

        re.setPattern("^\\s*#");
        if(line.isEmpty() || re.match(line).hasMatch() || line == QByteArray("\n", 1))
            continue;

        re.setPattern("^LocalSocket\\s+(?<varname>[a-zA-Z0-9:\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLocalSocket->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLocalSocket->setChecked(true);
            continue;
        }
        re.setPattern("^LocalSocket\\s+\"(?<varname>[a-zA-Z0-9:\\/. ]+)\"\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLocalSocket->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLocalSocket->setChecked(true);
            continue;
        }

        re.setPattern("^LocalSocketGroup\\s+(?<varname>[a-zA-Z0-9\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLocalSocketGroup->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLocalSocketGroup->setChecked(true);
            continue;
        }

        re.setPattern("^LocalSocketMode\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLocalSocketMode->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLocalSocketMode->setChecked(true);
            continue;
        }

        re.setPattern("^FixStaleSocket\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFixStaleSocket->setChecked(true);
                ui->checkBoxEnableFixStaleSocket->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFixStaleSocket->setChecked(false);
                ui->checkBoxEnableFixStaleSocket->setChecked(true);
            }
            continue;
        }

        re.setPattern("^TCPSocket\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxTCPSocket->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableTCPSocket->setChecked(true);
            continue;
        }

        re.setPattern("^TCPAddr\\s+(?<varname>[0-9.]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListTCPAddr->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListTCPAddr->setQStringList(tmp);
            ui->checkBoxEnableTCPAddr->setChecked(true);
            continue;
        }

        re.setPattern("^MaxConnectionQueueLength\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxConnectionQueueLength->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxConnectionQueueLength->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StreamMaxLength\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxStreamMaxLength->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableStreamMaxLength->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StreamMinPort\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxStreamMinPort->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableStreamMinPort->setChecked(true);
            continue;
        }

        re.setPattern("^StreamMaxPort\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxStreamMaxPort->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableStreamMaxPort->setChecked(true);
            continue;
        }

        re.setPattern("^MaxThreads\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxMaxThreads->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableMaxThreads->setChecked(true);
            continue;
        }

        re.setPattern("^ReadTimeout\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxReadTimeout->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableReadTimeout->setChecked(true);
            continue;
        }

        re.setPattern("^CommandReadTimeout\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxCommandReadTimeout->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableCommandReadTimeout->setChecked(true);
            continue;
        }

        re.setPattern("^SendBufTimeout\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxSendBufTimeout->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableSendBufTimeout->setChecked(true);
            continue;
        }

        re.setPattern("^MaxQueue\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxMaxQueue->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableMaxQueue->setChecked(true);
            continue;
        }

        re.setPattern("^IdleTimeout\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->spinBoxIdleTimeout->setValue(toClamInt(re.match(line).captured("varname")));
            ui->checkBoxEnableIdleTimeout->setChecked(true);
            continue;
        }

        re.setPattern("^ExcludePath\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListExcludePath->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListExcludePath->setQStringList(tmp);
            ui->checkBoxEnableExcludePath->setChecked(true);
            continue;
        }

        re.setPattern("^LogFile\\s+(?<varname>[a-zA-Z0-9:\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLogFile->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLogFile->setChecked(true);
            continue;
        }
        re.setPattern("^LogFile\\s+\"(?<varname>[a-zA-Z0-9:\\/. ]+)\"\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLogFile->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLogFile->setChecked(true);
            continue;
        }

        re.setPattern("^LogFileUnlock\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLogFileUnlock->setChecked(true);
                ui->checkBoxEnableLogFileUnlock->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLogFileUnlock->setChecked(false);
                ui->checkBoxEnableLogFileUnlock->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogFileMaxSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxLogFileMaxSize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableLogFileMaxSize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogTime\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLogTime->setChecked(true);
                ui->checkBoxEnableLogTime->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLogTime->setChecked(false);
                ui->checkBoxEnableLogTime->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogClean\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLogClean->setChecked(true);
                ui->checkBoxEnableLogClean->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLogClean->setChecked(false);
                ui->checkBoxEnableLogClean->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogSyslog\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLogSyslog->setChecked(true);
                ui->checkBoxEnableLogSyslog->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLogSyslog->setChecked(false);
                ui->checkBoxEnableLogSyslog->setChecked(true);
            }
            continue;
        }
        re.setPattern("^LogFacility\\s+(?<varname>[a-zA-Z0-9_]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditLogFacility->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableLogFacility->setChecked(true);
            continue;
        }

        re.setPattern("^LogVerbose\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLogVerbose->setChecked(true);
                ui->checkBoxEnableLogVerbose->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLogVerbose->setChecked(false);
                ui->checkBoxEnableLogVerbose->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogRotate\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLogRotate->setChecked(true);
                ui->checkBoxEnableLogRotate->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLogRotate->setChecked(false);
                ui->checkBoxEnableLogRotate->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ExtendedDetectionInfo\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxExtendedDetectionInfo->setChecked(true);
                ui->checkBoxEnableExtendedDetectionInfo->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxExtendedDetectionInfo->setChecked(false);
                ui->checkBoxEnableExtendedDetectionInfo->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PidFile\\s+(?<varname>[a-zA-Z0-9:\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditPidFile->setText(re.match(line).captured("varname"));
            ui->checkBoxEnablePidFile->setChecked(true);
            continue;
        }
        re.setPattern("^PidFile\\s+\"(?<varname>[a-zA-Z0-9:\\/. ]+)\"\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditPidFile->setText(re.match(line).captured("varname"));
            ui->checkBoxEnablePidFile->setChecked(true);
            continue;
        }

        re.setPattern("^TemporaryDirectory\\s+(?<varname>[a-zA-Z0-9:\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditTemporaryDirectory->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableTemporaryDirectory->setChecked(true);
            continue;
        }
        re.setPattern("^TemporaryDirectory\\s+\"(?<varname>[a-zA-Z0-9:\\/. ]+)\"\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditTemporaryDirectory->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableTemporaryDirectory->setChecked(true);
            continue;
        }

        re.setPattern("^DatabaseDirectory\\s+(?<varname>[a-zA-Z0-9:\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditDatabaseDirectory->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableDatabaseDirectory->setChecked(true);
            continue;
        }
        re.setPattern("^DatabaseDirectory\\s+\"(?<varname>[a-zA-Z0-9:\\/. ]+)\"\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditDatabaseDirectory->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableDatabaseDirectory->setChecked(true);
            continue;
        }

        re.setPattern("^OfficialDatabaseOnly\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxOfficialDatabaseOnly->setChecked(true);
                ui->checkBoxEnableOfficialDatabaseOnly->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxOfficialDatabaseOnly->setChecked(false);
                ui->checkBoxEnableOfficialDatabaseOnly->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxDirectoryRecursion\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxDirectoryRecursion->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxDirectoryRecursion->setChecked(true);
            }
            continue;
        }

        re.setPattern("^FollowDirectorySymlinks\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFollowDirectorySymlinks->setChecked(true);
                ui->checkBoxEnableFollowDirectorySymlinks->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFollowDirectorySymlinks->setChecked(false);
                ui->checkBoxEnableFollowDirectorySymlinks->setChecked(true);
            }
            continue;
        }

        re.setPattern("^FollowFileSymlinks\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFollowFileSymlinks->setChecked(true);
                ui->checkBoxEnableFollowFileSymlinks->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFollowFileSymlinks->setChecked(false);
                ui->checkBoxEnableFollowFileSymlinks->setChecked(true);
            }
            continue;
        }

        re.setPattern("^CrossFilesystems\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxCrossFilesystems->setChecked(true);
                ui->checkBoxEnableCrossFilesystems->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxCrossFilesystems->setChecked(false);
                ui->checkBoxEnableCrossFilesystems->setChecked(true);
            }
            continue;
        }

        re.setPattern("^SelfCheck\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxSelfCheck->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableSelfCheck->setChecked(true);
            }
            continue;
        }

        re.setPattern("^DisableCache\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxDisableCache->setChecked(true);
                ui->checkBoxEnableDisableCache->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxDisableCache->setChecked(false);
                ui->checkBoxEnableDisableCache->setChecked(true);
            }
            continue;
        }

        re.setPattern("^VirusEvent\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditVirusEvent->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableVirusEvent->setChecked(true);
            continue;
        }

        re.setPattern("^ExitOnOOM\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxExitOnOOM->setChecked(true);
                ui->checkBoxEnableExitOnOOM->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxExitOnOOM->setChecked(false);
                ui->checkBoxEnableExitOnOOM->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AllowAllMatchScan\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAllowAllMatchScan->setChecked(true);
                ui->checkBoxEnableAllowAllMatchScan->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAllowAllMatchScan->setChecked(false);
                ui->checkBoxEnableAllowAllMatchScan->setChecked(true);
            }
            continue;
        }

        re.setPattern("^Foreground\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxForeground->setChecked(true);
                ui->checkBoxEnableForeground->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxForeground->setChecked(false);
                ui->checkBoxEnableForeground->setChecked(true);
            }
            continue;
        }

        re.setPattern("^Debug\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxDebug->setChecked(true);
                ui->checkBoxEnableDebug->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxDebug->setChecked(false);
                ui->checkBoxEnableDebug->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LeaveTemporaryFiles\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxLeaveTemporaryFiles->setChecked(true);
                ui->checkBoxEnableLeaveTemporaryFiles->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxLeaveTemporaryFiles->setChecked(false);
                ui->checkBoxEnableLeaveTemporaryFiles->setChecked(true);
            }
            continue;
        }

        re.setPattern("^User\\s+(?<varname>[a-z-_]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditUser->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableUser->setChecked(true);
            continue;
        }

        re.setPattern("^Bytecode\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxBytecode->setChecked(true);
                ui->checkBoxEnableBytecode->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxBytecode->setChecked(false);
                ui->checkBoxEnableBytecode->setChecked(true);
            }
            continue;
        }

        re.setPattern("^BytecodeSecurity\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(re.match(line).captured("varname") == QString("TrustSigned")){
                ui->comboBoxBytecodeSecurity->setCurrentIndex(0);
                ui->checkBoxEnableBytecodeSecurity->setChecked(true);
            }else if(re.match(line).captured("varname") == QString("Paranoid")){
                ui->comboBoxBytecodeSecurity->setCurrentIndex(1);
                ui->checkBoxEnableBytecodeSecurity->setChecked(true);
            }
            continue;
        }

        re.setPattern("^BytecodeTimeout\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxBytecodeTimeout->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableBytecodeTimeout->setChecked(true);
            }
            continue;
        }

        re.setPattern("^BytecodeUnsigned\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxBytecodeUnsigned->setChecked(true);
                ui->checkBoxEnableBytecodeUnsigned->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxBytecodeUnsigned->setChecked(false);
                ui->checkBoxEnableBytecodeUnsigned->setChecked(true);
            }
            continue;
        }

        re.setPattern("^BytecodeMode\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(re.match(line).captured("varname") == QString("Auto")){
                ui->comboBoxBytecodeMode->setCurrentIndex(0);
                ui->checkBoxEnableBytecodeMode->setChecked(true);
            }else if(re.match(line).captured("varname") == QString("ForceJIT")){
                ui->comboBoxBytecodeMode->setCurrentIndex(1);
                ui->checkBoxEnableBytecodeMode->setChecked(true);
            }else if(re.match(line).captured("varname") == QString("ForceInterpreter")){
                ui->comboBoxBytecodeMode->setCurrentIndex(2);
                ui->checkBoxEnableBytecodeMode->setChecked(true);
            }else if(re.match(line).captured("varname") == QString("Test")){
                ui->comboBoxBytecodeMode->setCurrentIndex(3);
                ui->checkBoxEnableBytecodeMode->setChecked(true);
            }
            continue;
        }

        re.setPattern("^DetectPUA\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxDetectPUA->setChecked(true);
                ui->checkBoxEnableDetectPUA->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxDetectPUA->setChecked(false);
                ui->checkBoxEnableDetectPUA->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ExcludePUA\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListExcludePUA->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListExcludePUA->setQStringList(tmp);
            ui->checkBoxEnableExcludePUA->setChecked(true);
            continue;
        }

        re.setPattern("^IncludePUA\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListIncludePUA->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListIncludePUA->setQStringList(tmp);
            ui->checkBoxEnableIncludePUA->setChecked(true);
            continue;
        }

        re.setPattern("^ScanPE\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanPE->setChecked(true);
                ui->checkBoxEnableScanPE->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanPE->setChecked(false);
                ui->checkBoxEnableScanPE->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanELF\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanELF->setChecked(true);
                ui->checkBoxEnableScanELF->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanELF->setChecked(false);
                ui->checkBoxEnableScanELF->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanMail\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanMail->setChecked(true);
                ui->checkBoxEnableScanMail->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanMail->setChecked(false);
                ui->checkBoxEnableScanMail->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanPartialMessages\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanPartialMessages->setChecked(true);
                ui->checkBoxEnableScanPartialMessages->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanPartialMessages->setChecked(false);
                ui->checkBoxEnableScanPartialMessages->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PhishingSignatures\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxPhishingSignatures->setChecked(true);
                ui->checkBoxEnablePhishingSignatures->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxPhishingSignatures->setChecked(false);
                ui->checkBoxEnablePhishingSignatures->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PhishingScanURLs\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxPhishingScanURLs->setChecked(true);
                ui->checkBoxEnablePhishingScanURLs->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxPhishingScanURLs->setChecked(false);
                ui->checkBoxEnablePhishingScanURLs->setChecked(true);
            }
            continue;
        }

        re.setPattern("^HeuristicAlerts\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxHeuristicAlerts->setChecked(true);
                ui->checkBoxEnableHeuristicAlerts->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxHeuristicAlerts->setChecked(false);
                ui->checkBoxEnableHeuristicAlerts->setChecked(true);
            }
            continue;
        }

        re.setPattern("^HeuristicScanPrecedence\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxHeuristicScanPrecedence->setChecked(true);
                ui->checkBoxEnableHeuristicScanPrecedence->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxHeuristicScanPrecedence->setChecked(false);
                ui->checkBoxEnableHeuristicScanPrecedence->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StructuredDataDetection\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxStructuredDataDetection->setChecked(true);
                ui->checkBoxEnableStructuredDataDetection->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxStructuredDataDetection->setChecked(false);
                ui->checkBoxEnableStructuredDataDetection->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StructuredMinCreditCardCount\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxStructuredMinCreditCardCount->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableStructuredMinCreditCardCount->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StructuredMinSSNCount\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxStructuredMinSSNCount->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableStructuredMinSSNCount->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StructuredSSNFormatNormal\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxStructuredSSNFormatNormal->setChecked(true);
                ui->checkBoxEnableStructuredSSNFormatNormal->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxStructuredSSNFormatNormal->setChecked(false);
                ui->checkBoxEnableStructuredSSNFormatNormal->setChecked(true);
            }
            continue;
        }

        re.setPattern("^StructuredSSNFormatStripped\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxStructuredSSNFormatStripped->setChecked(true);
                ui->checkBoxEnableStructuredSSNFormatStripped->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxStructuredSSNFormatStripped->setChecked(false);
                ui->checkBoxEnableStructuredSSNFormatStripped->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanHTML\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanHTML->setChecked(true);
                ui->checkBoxEnableScanHTML->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanHTML->setChecked(false);
                ui->checkBoxEnableScanHTML->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanOLE2\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanOLE2->setChecked(true);
                ui->checkBoxEnableScanOLE2->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanOLE2->setChecked(false);
                ui->checkBoxEnableScanOLE2->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanPDF\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanPDF->setChecked(true);
                ui->checkBoxEnableScanPDF->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanPDF->setChecked(false);
                ui->checkBoxEnableScanPDF->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanSWF\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanSWF->setChecked(true);
                ui->checkBoxEnableScanSWF->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanSWF->setChecked(false);
                ui->checkBoxEnableScanSWF->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanXMLDOCS\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanXMLDOCS->setChecked(true);
                ui->checkBoxEnableScanXMLDOCS->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanXMLDOCS->setChecked(false);
                ui->checkBoxEnableScanXMLDOCS->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanHWP3\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanHWP3->setChecked(true);
                ui->checkBoxEnableScanHWP3->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanHWP3->setChecked(false);
                ui->checkBoxEnableScanHWP3->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScanArchive\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanArchive->setChecked(true);
                ui->checkBoxEnableScanArchive->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanArchive->setChecked(false);
                ui->checkBoxEnableScanArchive->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertBrokenExecutables\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertBrokenExecutables->setChecked(true);
                ui->checkBoxEnableAlertBrokenExecutables->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertBrokenExecutables->setChecked(false);
                ui->checkBoxEnableAlertBrokenExecutables->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertEncrypted\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertEncrypted->setChecked(true);
                ui->checkBoxEnableAlertEncrypted->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertEncrypted->setChecked(false);
                ui->checkBoxEnableAlertEncrypted->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertEncryptedArchive\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertEncryptedArchive->setChecked(true);
                ui->checkBoxEnableAlertEncryptedArchive->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertEncryptedArchive->setChecked(false);
                ui->checkBoxEnableAlertEncryptedArchive->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertEncryptedDoc\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertEncryptedDoc->setChecked(true);
                ui->checkBoxEnableAlertEncryptedDoc->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertEncryptedDoc->setChecked(false);
                ui->checkBoxEnableAlertEncryptedDoc->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertOLE2Macros\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertOLE2Macros->setChecked(true);
                ui->checkBoxEnableAlertOLE2Macros->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertOLE2Macros->setChecked(false);
                ui->checkBoxEnableAlertOLE2Macros->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertExceedsMax\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertExceedsMax->setChecked(true);
                ui->checkBoxEnableAlertExceedsMax->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertExceedsMax->setChecked(false);
                ui->checkBoxEnableAlertExceedsMax->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertExceedsMax\\s*$");
        if(re.match(line).hasMatch()){
            ui->checkBoxAlertExceedsMax->setChecked(false);
            ui->checkBoxEnableAlertExceedsMax->setChecked(true);
            continue;
        }

        re.setPattern("^AlertPhishingSSLMismatch\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertPhishingSSLMismatch->setChecked(true);
                ui->checkBoxEnableAlertPhishingSSLMismatch->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertPhishingSSLMismatch->setChecked(false);
                ui->checkBoxEnableAlertPhishingSSLMismatch->setChecked(true);
            }
            continue;
        }
        re.setPattern("^AlertPhishingSSLMismatch\\s*$");
        if(re.match(line).hasMatch()){
            ui->checkBoxAlertPhishingSSLMismatch->setChecked(false);
            ui->checkBoxEnableAlertPhishingSSLMismatch->setChecked(true);
            continue;
        }

        re.setPattern("^AlertPhishingCloak\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertPhishingCloak->setChecked(true);
                ui->checkBoxEnableAlertPhishingCloak->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertPhishingCloak->setChecked(false);
                ui->checkBoxEnableAlertPhishingCloak->setChecked(true);
            }
            continue;
        }

        re.setPattern("^AlertPartitionIntersection\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxAlertPartitionIntersection->setChecked(true);
                ui->checkBoxEnableAlertPartitionIntersection->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxAlertPartitionIntersection->setChecked(false);
                ui->checkBoxEnableAlertPartitionIntersection->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ForceToDisk\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxForceToDisk->setChecked(true);
                ui->checkBoxEnableForceToDisk->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxForceToDisk->setChecked(false);
                ui->checkBoxEnableForceToDisk->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxScanTime\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxScanTime->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxScanTime->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxScanSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxScanSize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxScanSize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxFileSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxFileSize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxFileSize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxRecursion\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxRecursion->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxRecursion->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxFiles\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxFiles->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxFiles->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxEmbeddedPE\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxEmbeddedPE->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxEmbeddedPE->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxHTMLNormalize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxHTMLNormalize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxHTMLNormalize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxHTMLNoTags\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxHTMLNoTags->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxHTMLNoTags->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxScriptNormalize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxScriptNormalize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxScriptNormalize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxZipTypeRcg\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxZipTypeRcg->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxZipTypeRcg->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxPartitions\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxPartitions->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxPartitions->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxIconsPE\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxIconsPE->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxIconsPE->setChecked(true);
            }
            continue;
        }

        re.setPattern("^MaxRecHWP3\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxMaxRecHWP3->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableMaxRecHWP3->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PCREMatchLimit\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxPCREMatchLimit->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnablePCREMatchLimit->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PCRERecMatchLimit\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxPCRERecMatchLimit->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnablePCRERecMatchLimit->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PCREMaxFileSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxPCREMaxFileSize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnablePCREMaxFileSize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessMountPath\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListOnAccessMountPath->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListOnAccessMountPath->setQStringList(tmp);
            ui->checkBoxEnableOnAccessMountPath->setChecked(true);
            continue;
        }

        re.setPattern("^OnAccessIncludePath\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListOnAccessIncludePath->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListOnAccessIncludePath->setQStringList(tmp);
            ui->checkBoxEnableOnAccessIncludePath->setChecked(true);
            continue;
        }

        re.setPattern("^OnAccessExcludePath\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListOnAccessExcludePath->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListOnAccessExcludePath->setQStringList(tmp);
            ui->checkBoxEnableOnAccessExcludePath->setChecked(true);
            continue;
        }

        re.setPattern("^OnAccessExcludeRootUID\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxOnAccessExcludeRootUID->setChecked(true);
                ui->checkBoxEnableOnAccessExcludeRootUID->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxOnAccessExcludeRootUID->setChecked(false);
                ui->checkBoxEnableOnAccessExcludeRootUID->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessExcludeUID\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QList<int> tmp = ui->listSpinBoxOnAccessExcludeUID->getQListInt();
            tmp.append(re.match(line).captured("varname").toInt());
            ui->listSpinBoxOnAccessExcludeUID->setQListInt(tmp);
            ui->checkBoxEnableOnAccessExcludeUID->setChecked(true);
            continue;
        }

        re.setPattern("^OnAccessExcludeUname\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListOnAccessExcludeUname->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListOnAccessExcludeUname->setQStringList(tmp);
            ui->checkBoxEnableOnAccessExcludeUname->setChecked(true);
            continue;
        }

        re.setPattern("^OnAccessMaxFileSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxOnAccessMaxFileSize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableOnAccessMaxFileSize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessDisableDDD\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxOnAccessDisableDDD->setChecked(true);
                ui->checkBoxEnableOnAccessDisableDDD->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxOnAccessDisableDDD->setChecked(false);
                ui->checkBoxEnableOnAccessDisableDDD->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessPrevention\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxOnAccessPrevention->setChecked(true);
                ui->checkBoxEnableOnAccessPrevention->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxOnAccessPrevention->setChecked(false);
                ui->checkBoxEnableOnAccessPrevention->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessExtraScanning\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxOnAccessExtraScanning->setChecked(true);
                ui->checkBoxEnableOnAccessExtraScanning->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxOnAccessExtraScanning->setChecked(false);
                ui->checkBoxEnableOnAccessExtraScanning->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessCurlTimeout\\s+(?<varname>[0-9L]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxOnAccessCurlTimeout->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableOnAccessCurlTimeout->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessMaxThreads\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxOnAccessMaxThreads->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableOnAccessMaxThreads->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessRetryAttempts\\s+(?<varname>[0-9]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxOnAccessRetryAttempts->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableOnAccessRetryAttempts->setChecked(true);
            }
            continue;
        }

        re.setPattern("^OnAccessDenyOnError\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxOnAccessDenyOnError->setChecked(true);
                ui->checkBoxEnableOnAccessDenyOnError->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxOnAccessDenyOnError->setChecked(false);
                ui->checkBoxEnableOnAccessDenyOnError->setChecked(true);
            }
            continue;
        }

        re.setPattern("^DisableCertCheck\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxDisableCertCheck->setChecked(true);
                ui->checkBoxEnableDisableCertCheck->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxDisableCertCheck->setChecked(false);
                ui->checkBoxEnableDisableCertCheck->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PreludeEnable\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxPreludeEnable->setChecked(true);
                ui->checkBoxEnablePreludeEnable->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxPreludeEnable->setChecked(false);
                ui->checkBoxEnablePreludeEnable->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PreludeEnable\\s*$");
        if(re.match(line).hasMatch()){
            ui->checkBoxPreludeEnable->setChecked(false);
            ui->checkBoxEnablePreludeEnable->setChecked(true);
            continue;
        }

        re.setPattern("^PreludeAnalyzerName\\s+(?<varname>[a-zA-Z0-9-:\\/.]+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditPreludeAnalyzerName->setText(re.match(line).captured("varname"));
            ui->checkBoxEnablePreludeEnable->setEnabled(true);
            ui->checkBoxEnablePreludeEnable->setChecked(true);
            continue;
        }

        re.setPattern("^ScanOnAccess\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxScanOnAccess->setChecked(true);
                ui->checkBoxEnableScanOnAccess->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxScanOnAccess->setChecked(false);
                ui->checkBoxEnableScanOnAccess->setChecked(true);
            }
            continue;
        }

        oldErrClamdconf.append(line);
    }
    file.close();
    fileUiToClamdconf(&oldClamdconf);
    return true;
}

bool ConfigureDialogCurrent::fileFreshclamconfToUI(QString filename){
    disableAllFreshclamconf();
    QFile file(filename);
    if(!file.exists())
        return false;
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    while(!file.atEnd()){
        QRegularExpression re;
        QByteArray line = file.readLine();
        re.setPattern("^\\s*#");
        if(line.isEmpty() || re.match(line).hasMatch() || line == QByteArray("\n", 1))
            continue;

        re.setPattern("^LogFileMaxSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxFreshLogFileMaxSize->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableFreshLogFileMaxSize->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogTime\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshLogTime->setChecked(true);
                ui->checkBoxEnableFreshLogTime->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshLogTime->setChecked(false);
                ui->checkBoxEnableFreshLogTime->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogSyslog\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshLogSyslog->setChecked(true);
                ui->checkBoxEnableFreshLogSyslog->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshLogSyslog->setChecked(false);
                ui->checkBoxEnableFreshLogSyslog->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogFacility\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshLogFacility->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshLogFacility->setChecked(true);
            continue;
        }

        re.setPattern("^LogVerbose\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshLogVerbose->setChecked(true);
                ui->checkBoxEnableFreshLogVerbose->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshLogVerbose->setChecked(false);
                ui->checkBoxEnableFreshLogVerbose->setChecked(true);
            }
            continue;
        }

        re.setPattern("^LogRotate\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshLogRotate->setChecked(true);
                ui->checkBoxEnableFreshLogRotate->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshLogRotate->setChecked(false);
                ui->checkBoxEnableFreshLogRotate->setChecked(true);
            }
            continue;
        }

        re.setPattern("^PidFile\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshPidFile->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshPidFile->setChecked(true);
            continue;
        }

        re.setPattern("^DatabaseDirectory\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshDatabaseDirectory->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshDatabaseDirectory->setChecked(true);
            continue;
        }

        re.setPattern("^Foreground\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshForeground->setChecked(true);
                ui->checkBoxEnableFreshForeground->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshForeground->setChecked(false);
                ui->checkBoxEnableFreshForeground->setChecked(true);
            }
            continue;
        }

        re.setPattern("^Debug\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshDebug->setChecked(true);
                ui->checkBoxEnableFreshDebug->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshDebug->setChecked(false);
                ui->checkBoxEnableFreshDebug->setChecked(true);
            }
            continue;
        }

        re.setPattern("^UpdateLogFile\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshUpdateLogFile->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshUpdateLogFile->setChecked(true);
            continue;
        }

        re.setPattern("^DatabaseOwner\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshDatabaseOwner->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshDatabaseOwner->setChecked(true);
            continue;
        }

        re.setPattern("^Checks\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxFreshChecks->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableFreshChecks->setChecked(true);
            }
            continue;
        }

        re.setPattern("^DNSDatabaseInfo\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshDNSDatabaseInfo->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshDNSDatabaseInfo->setChecked(true);
            continue;
        }

        re.setPattern("^DatabaseMirror\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            //ui->lineEditFreshDatabaseMirror->setText(re.match(line).captured("varname"));
            QStringList tmp = ui->stringListFreshDatabaseMirror->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListFreshDatabaseMirror->setQStringList(tmp);
            ui->checkBoxEnableFreshDatabaseMirror->setChecked(true);
            continue;
        }

        re.setPattern("^PrivateMirror\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListFreshPrivateMirror->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListFreshPrivateMirror->setQStringList(tmp);
            ui->checkBoxEnableFreshPrivateMirror->setChecked(true);
            continue;
        }

        re.setPattern("^MaxAttempts\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxFreshMaxAttempts->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableFreshMaxAttempts->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ScriptedUpdates\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshScriptedUpdates->setChecked(true);
                ui->checkBoxEnableFreshScriptedUpdates->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshScriptedUpdates->setChecked(false);
                ui->checkBoxEnableFreshScriptedUpdates->setChecked(true);
            }
            continue;
        }

        re.setPattern("^TestDatabases\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshTestDatabases->setChecked(true);
                ui->checkBoxEnableFreshTestDatabases->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshTestDatabases->setChecked(false);
                ui->checkBoxEnableFreshTestDatabases->setChecked(true);
            }
            continue;
        }

        re.setPattern("^CompressLocalDatabase\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshCompressLocalDatabase->setChecked(true);
                ui->checkBoxEnableFreshCompressLocalDatabase->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshCompressLocalDatabase->setChecked(false);
                ui->checkBoxEnableFreshCompressLocalDatabase->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ExtraDatabase\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListFreshExtraDatabase->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListFreshExtraDatabase->setQStringList(tmp);
            ui->checkBoxEnableFreshExtraDatabase->setChecked(true);
            continue;
        }

        re.setPattern("^ExcludeDatabase\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListFreshExcludeDatabase->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListFreshExcludeDatabase->setQStringList(tmp);
            ui->checkBoxEnableFreshExcludeDatabase->setChecked(true);
            continue;
        }

        re.setPattern("^DatabaseCustomURL\\s+(?<varname>[a-zA-Z0-9\\/.^$]+)\\s*$");
        if(re.match(line).hasMatch()){
            QStringList tmp = ui->stringListFreshDatabaseCustomURL->getQStringList();
            tmp.append(re.match(line).captured("varname"));
            ui->stringListFreshDatabaseCustomURL->setQStringList(tmp);
            ui->checkBoxEnableFreshDatabaseCustomURL->setChecked(true);
            continue;
        }

        re.setPattern("^HTTPProxyServer\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshHTTPProxyServer->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshHTTPProxyServer->setChecked(true);
            continue;
        }

        re.setPattern("^LogFileMaxSize\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxFreshHTTPProxyPort->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableFreshHTTPProxyPort->setChecked(true);
            }
            continue;
        }

        re.setPattern("^HTTPProxyUsername\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshHTTPProxyUsername->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshHTTPProxyUsername->setChecked(true);
            continue;
        }

        re.setPattern("^HTTPProxyPassword\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshHTTPProxyPassword->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshHTTPProxyPassword->setChecked(true);
            continue;
        }

        re.setPattern("^HTTPUserAgent\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshHTTPUserAgent->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshHTTPUserAgent->setChecked(true);
            continue;
        }

        re.setPattern("^NotifyClamd\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshNotifyClamd->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshNotifyClamd->setChecked(true);
            continue;
        }


        re.setPattern("^OnUpdateExecute\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshOnUpdateExecute->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshOnUpdateExecute->setChecked(true);
            continue;
        }

        re.setPattern("^OnErrorExecute\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshOnErrorExecute->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshOnErrorExecute->setChecked(true);
            continue;
        }

        re.setPattern("^OnOutdatedExecute\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshOnOutdatedExecute->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshOnOutdatedExecute->setChecked(true);
            continue;
        }

        re.setPattern("^LocalIPAddress\\s+(?<varname>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ui->lineEditFreshLocalIPAddress->setText(re.match(line).captured("varname"));
            ui->checkBoxEnableFreshLocalIPAddress->setChecked(true);
            continue;
        }

        re.setPattern("^ConnectTimeout\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxFreshConnectTimeout->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableFreshConnectTimeout->setChecked(true);
            }
            continue;
        }

        re.setPattern("^ReceiveTimeout\\s+(?<varname>[0-9kKmM]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(toClamInt(re.match(line).captured("varname")) != -1){
                ui->spinBoxFreshReceiveTimeout->setValue(toClamInt(re.match(line).captured("varname")));
                ui->checkBoxEnableFreshReceiveTimeout->setChecked(true);
            }
            continue;
        }

        re.setPattern("^SafeBrowsing\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshSafeBrowsing->setChecked(true);
                ui->checkBoxEnableFreshSafeBrowsing->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshSafeBrowsing->setChecked(false);
                ui->checkBoxEnableFreshSafeBrowsing->setChecked(true);
            }
            continue;
        }

        re.setPattern("^Bytecode\\s+(?<varname>[a-zA-Z]+)\\s*$");
        if(re.match(line).hasMatch()){
            if(matchBoolTrue(re, line)){
                ui->checkBoxFreshBytecode->setChecked(true);
                ui->checkBoxEnableFreshBytecode->setChecked(true);
            }else if(matchBoolFalse(re, line)){
                ui->checkBoxFreshBytecode->setChecked(false);
                ui->checkBoxEnableFreshBytecode->setChecked(true);
            }
            continue;
        }

        oldErrFreshclamconf.append(line);
    }
    file.close();
    fileUiToFreshclamconf(&oldFreshclamconf);
    return true;
}

void ConfigureDialogCurrent::addExclusionClamdconf(QByteArray exclude_filename){
    ui->listWidgetMain->setCurrentRow(ClamOneConfigStackOrder::ConfigClamdconf);
    ui->scrollAreaNetSock->verticalScrollBar()->setValue(ui->scrollAreaNetSock->verticalScrollBar()->maximum());
    ui->checkBoxEnableExcludePath->setChecked(true);
    QStringList expath = ui->stringListExcludePath->getQStringList();
    if(expath.contains(QString(exclude_filename))){
        hide();
        return;
    }
    expath = expath.toSet().toList();
    expath.append(QString(exclude_filename));
    ui->stringListExcludePath->setQStringList(expath);
    on_pushButtonOk_clicked();
}

bool ConfigureDialogCurrent::fileUiToClamdconf(QByteArray *out){
    LINE_END
    (*out) = QByteArray("#Automatically Generated by clamav-daemon postinst")+end+
             QByteArray("#To reconfigure clamd run #dpkg-reconfigure clamav-daemon")+end+
             QByteArray("#Please read /usr/share/doc/clamav-daemon/README.Debian.gz for details")+end;
    if(ui->checkBoxEnableAlertExceedsMax->isChecked()){
        if(ui->checkBoxAlertExceedsMax->isChecked()){
            (*out).append(QByteArray("AlertExceedsMax true")+end);
        }else{
            (*out).append(QByteArray("AlertExceedsMax false")+end);
        }
    }
    if(ui->checkBoxEnablePreludeEnable->isChecked()){
        if(ui->checkBoxPreludeEnable->isChecked() && !ui->lineEditPreludeAnalyzerName->text().isEmpty()){
            (*out).append(QByteArray("PreludeEnable yes")+end);
            (*out).append(QByteArray("PreludeAnalyzerName ")+ui->lineEditPreludeAnalyzerName->text().toLocal8Bit()+end);
        }else{
            (*out).append(QByteArray("PreludeEnable no")+end);
            if(!ui->lineEditPreludeAnalyzerName->text().isEmpty())
                (*out).append(QByteArray("PreludeAnalyzerName ")+ui->lineEditPreludeAnalyzerName->text().toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableLogFile->isChecked()){
        (*out).append(QByteArray("LogFile ")+ui->lineEditLogFile->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableLogFileUnlock->isChecked()){
        if(ui->checkBoxLogFileUnlock->isChecked()){
            (*out).append(QByteArray("LogFileUnlock true")+end);
        }else{
            (*out).append(QByteArray("LogFileUnlock false")+end);
        }
    }
    if(ui->checkBoxEnableLogFileMaxSize->isChecked()){
        (*out).append(QByteArray("LogFileMaxSize ")+toClamInt(ui->spinBoxLogFileMaxSize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableLogTime->isChecked()){
        if(ui->checkBoxLogTime->isChecked()){
            (*out).append(QByteArray("LogTime true")+end);
        }else{
            (*out).append(QByteArray("LogTime false")+end);
        }
    }
    if(ui->checkBoxEnableLogClean->isChecked()){
        if(ui->checkBoxLogClean->isChecked()){
            (*out).append(QByteArray("LogClean true")+end);
        }else{
            (*out).append(QByteArray("LogClean false")+end);
        }
    }
    if(ui->checkBoxEnableLogSyslog->isChecked()){
        if(ui->checkBoxLogSyslog->isChecked()){
            (*out).append(QByteArray("LogSyslog true")+end);
        }else{
            (*out).append(QByteArray("LogSyslog false")+end);
        }
    }
    if(ui->checkBoxEnableLogFacility->isChecked()){
        (*out).append(QByteArray("LogFacility ")+ui->lineEditLogFacility->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableLogVerbose->isChecked()){
        if(ui->checkBoxLogVerbose->isChecked()){
            (*out).append(QByteArray("LogVerbose true")+end);
        }else{
            (*out).append(QByteArray("LogVerbose false")+end);
        }
    }
    if(ui->checkBoxEnableLogRotate->isChecked()){
        if(ui->checkBoxLogRotate->isChecked()){
            (*out).append(QByteArray("LogRotate true")+end);
        }else{
            (*out).append(QByteArray("LogRotate false")+end);
        }
    }
    if(ui->checkBoxEnableExtendedDetectionInfo->isChecked()){
        if(ui->checkBoxExtendedDetectionInfo->isChecked()){
            (*out).append(QByteArray("ExtendedDetectionInfo true")+end);
        }else{
            (*out).append(QByteArray("ExtendedDetectionInfo false")+end);
        }
    }
    if(ui->checkBoxEnablePidFile->isChecked()){
        (*out).append(QByteArray("PidFile ")+ui->lineEditPidFile->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableDatabaseDirectory->isChecked()){
        (*out).append(QByteArray("DatabaseDirectory ")+ui->lineEditDatabaseDirectory->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableOfficialDatabaseOnly->isChecked()){
        if(ui->checkBoxOfficialDatabaseOnly->isChecked()){
            (*out).append(QByteArray("OfficialDatabaseOnly true")+end);
        }else{
            (*out).append(QByteArray("OfficialDatabaseOnly false")+end);
        }
    }
    if(ui->checkBoxEnableLocalSocket->isChecked()){
        (*out).append(QByteArray("LocalSocket ")+ui->lineEditLocalSocket->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableLocalSocketGroup->isChecked()){
        (*out).append(QByteArray("LocalSocketGroup ")+ui->lineEditLocalSocketGroup->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableLocalSocketMode->isChecked()){
        (*out).append(QByteArray("LocalSocketMode ")+ui->lineEditLocalSocketMode->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableTemporaryDirectory->isChecked()){
        (*out).append(QByteArray("TemporaryDirectory ")+ui->lineEditTemporaryDirectory->text().toLocal8Bit()+end);
    }else{
        (*out).append(QByteArray("# TemporaryDirectory is not set to its default /tmp here to make overriding")+end+
                      QByteArray("# the default with environment variables TMPDIR/TMP/TEMP possible")+end);
    }
    if(ui->checkBoxEnableFixStaleSocket->isChecked()){
        if(ui->checkBoxFixStaleSocket->isChecked()){
            (*out).append(QByteArray("FixStaleSocket true")+end);
        }else{
            (*out).append(QByteArray("FixStaleSocket false")+end);
        }
    }
    if(ui->checkBoxEnableTCPSocket->isChecked()){
        (*out).append(QByteArray("TCPSocket ")+QString::number(ui->spinBoxTCPSocket->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableTCPAddr->isChecked()){
        foreach(QString line, ui->stringListTCPAddr->getQStringList()){
            (*out).append(QByteArray("TCPAddr ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableMaxConnectionQueueLength->isChecked()){
        (*out).append(QByteArray("MaxConnectionQueueLength ")+QString::number(ui->spinBoxMaxConnectionQueueLength->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableStreamMaxLength->isChecked()){
        (*out).append(QByteArray("StreamMaxLength ")+toClamInt(ui->spinBoxStreamMaxLength->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableStreamMinPort->isChecked()){
        (*out).append(QByteArray("StreamMinPort ")+QString::number(ui->spinBoxStreamMinPort->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableStreamMaxPort->isChecked()){
        (*out).append(QByteArray("StreamMaxPort ")+QString::number(ui->spinBoxStreamMaxPort->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxThreads->isChecked()){
        (*out).append(QByteArray("MaxThreads ")+QString::number(ui->spinBoxMaxThreads->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableReadTimeout->isChecked()){
        (*out).append(QByteArray("ReadTimeout ")+QString::number(ui->spinBoxReadTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableCommandReadTimeout->isChecked()){
        (*out).append(QByteArray("CommandReadTimeout ")+QString::number(ui->spinBoxCommandReadTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableSendBufTimeout->isChecked()){
        (*out).append(QByteArray("SendBufTimeout ")+QString::number(ui->spinBoxSendBufTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxQueue->isChecked()){
        (*out).append(QByteArray("MaxQueue ")+QString::number(ui->spinBoxMaxQueue->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableIdleTimeout->isChecked()){
        (*out).append(QByteArray("IdleTimeout ")+QString::number(ui->spinBoxIdleTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableExcludePath->isChecked()){
        foreach(QString line, ui->stringListExcludePath->getQStringList()){
            (*out).append(QByteArray("ExcludePath ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableMaxDirectoryRecursion->isChecked()){
        (*out).append(QByteArray("MaxDirectoryRecursion ")+QString::number(ui->spinBoxMaxDirectoryRecursion->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFollowDirectorySymlinks->isChecked()){
        if(ui->checkBoxFollowDirectorySymlinks->isChecked()){
            (*out).append(QByteArray("FollowDirectorySymlinks true")+end);
        }else{
            (*out).append(QByteArray("FollowDirectorySymlinks false")+end);
        }
    }
    if(ui->checkBoxEnableFollowFileSymlinks->isChecked()){
        if(ui->checkBoxFollowFileSymlinks->isChecked()){
            (*out).append(QByteArray("FollowFileSymlinks true")+end);
        }else{
            (*out).append(QByteArray("FollowFileSymlinks false")+end);
        }
    }
    if(ui->checkBoxEnableCrossFilesystems->isChecked()){
        if(ui->checkBoxCrossFilesystems->isChecked()){
            (*out).append(QByteArray("CrossFilesystems true")+end);
        }else{
            (*out).append(QByteArray("CrossFilesystems false")+end);
        }
    }
    if(ui->checkBoxEnableSelfCheck->isChecked()){
        (*out).append(QByteArray("SelfCheck ")+QString::number(ui->spinBoxSelfCheck->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableDisableCache->isChecked()){
        if(ui->checkBoxDisableCache->isChecked()){
            (*out).append(QByteArray("DisableCache true")+end);
        }else{
            (*out).append(QByteArray("DisableCache false")+end);
        }
    }
    if(ui->checkBoxEnableVirusEvent->isChecked()){
        (*out).append(QByteArray("VirusEvent ")+ui->lineEditVirusEvent->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableExitOnOOM->isChecked()){
        if(ui->checkBoxExitOnOOM->isChecked()){
            (*out).append(QByteArray("ExitOnOOM true")+end);
        }else{
            (*out).append(QByteArray("ExitOnOOM false")+end);
        }
    }
    if(ui->checkBoxEnableAllowAllMatchScan->isChecked()){
        if(ui->checkBoxAllowAllMatchScan->isChecked()){
            (*out).append(QByteArray("AllowAllMatchScan true")+end);
        }else{
            (*out).append(QByteArray("AllowAllMatchScan false")+end);
        }
    }
    if(ui->checkBoxEnableForeground->isChecked()){
        if(ui->checkBoxForeground->isChecked()){
            (*out).append(QByteArray("Foreground true")+end);
        }else{
            (*out).append(QByteArray("Foreground false")+end);
        }
    }
    if(ui->checkBoxEnableDebug->isChecked()){
        if(ui->checkBoxDebug->isChecked()){
            (*out).append(QByteArray("Debug true")+end);
        }else{
            (*out).append(QByteArray("Debug false")+end);
        }
    }
    if(ui->checkBoxEnableLeaveTemporaryFiles->isChecked()){
        if(ui->checkBoxLeaveTemporaryFiles->isChecked()){
            (*out).append(QByteArray("LeaveTemporaryFiles true")+end);
        }else{
            (*out).append(QByteArray("LeaveTemporaryFiles false")+end);
        }
    }
    if(ui->checkBoxEnableUser->isChecked()){
        (*out).append(QByteArray("User ")+ui->lineEditUser->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableBytecode->isChecked()){
        if(ui->checkBoxBytecode->isChecked()){
            (*out).append(QByteArray("Bytecode true")+end);
        }else{
            (*out).append(QByteArray("Bytecode false")+end);
        }
    }
    if(ui->checkBoxEnableBytecodeSecurity->isChecked()){
        (*out).append(QByteArray("BytecodeSecurity ")+ui->comboBoxBytecodeSecurity->currentText().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableBytecodeTimeout->isChecked()){
        (*out).append(QByteArray("BytecodeTimeout ")+QString::number(ui->spinBoxBytecodeTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableBytecodeUnsigned->isChecked()){
        if(ui->checkBoxBytecodeUnsigned->isChecked()){
            (*out).append(QByteArray("BytecodeUnsigned yes")+end);
        }else{
            (*out).append(QByteArray("BytecodeUnsigned no")+end);
        }
    }
    if(ui->checkBoxEnableBytecodeMode->isChecked()){
        (*out).append(QByteArray("BytecodeMode ")+ui->comboBoxBytecodeMode->currentText().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableDetectPUA->isChecked()){
        if(ui->checkBoxDetectPUA->isChecked()){
            (*out).append(QByteArray("DetectPUA true")+end);
        }else{
            (*out).append(QByteArray("DetectPUA false")+end);
        }
    }
    if(ui->checkBoxEnableExcludePUA->isChecked()){
        foreach(QString line, ui->stringListExcludePUA->getQStringList()){
            (*out).append(QByteArray("ExcludePUA ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableIncludePUA->isChecked()){
        foreach(QString line, ui->stringListIncludePUA->getQStringList()){
            (*out).append(QByteArray("IncludePUA ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableScanPE->isChecked()){
        if(ui->checkBoxScanPE->isChecked()){
            (*out).append(QByteArray("ScanPE true")+end);
        }else{
            (*out).append(QByteArray("ScanPE false")+end);
        }
    }
    if(ui->checkBoxEnableScanELF->isChecked()){
        if(ui->checkBoxScanELF->isChecked()){
            (*out).append(QByteArray("ScanELF true")+end);
        }else{
            (*out).append(QByteArray("ScanELF false")+end);
        }
    }
    if(ui->checkBoxEnableScanMail->isChecked()){
        if(ui->checkBoxScanMail->isChecked()){
            (*out).append(QByteArray("ScanMail true")+end);
        }else{
            (*out).append(QByteArray("ScanMail false")+end);
        }
    }
    if(ui->checkBoxEnableScanPartialMessages->isChecked()){
        if(ui->checkBoxScanPartialMessages->isChecked()){
            (*out).append(QByteArray("ScanPartialMessages true")+end);
        }else{
            (*out).append(QByteArray("ScanPartialMessages false")+end);
        }
    }
    if(ui->checkBoxEnablePhishingSignatures->isChecked()){
        if(ui->checkBoxPhishingSignatures->isChecked()){
            (*out).append(QByteArray("PhishingSignatures true")+end);
        }else{
            (*out).append(QByteArray("PhishingSignatures false")+end);
        }
    }
    if(ui->checkBoxEnablePhishingScanURLs->isChecked()){
        if(ui->checkBoxPhishingScanURLs->isChecked()){
            (*out).append(QByteArray("PhishingScanURLs true")+end);
        }else{
            (*out).append(QByteArray("PhishingScanURLs false")+end);
        }
    }
    if(ui->checkBoxEnableHeuristicAlerts->isChecked()){
        if(ui->checkBoxHeuristicAlerts->isChecked()){
            (*out).append(QByteArray("HeuristicAlerts yes")+end);
        }else{
            (*out).append(QByteArray("HeuristicAlerts no")+end);
        }
    }
    if(ui->checkBoxEnableHeuristicScanPrecedence->isChecked()){
        if(ui->checkBoxHeuristicScanPrecedence->isChecked()){
            (*out).append(QByteArray("HeuristicScanPrecedence true")+end);
        }else{
            (*out).append(QByteArray("HeuristicScanPrecedence false")+end);
        }
    }
    if(ui->checkBoxEnableStructuredDataDetection->isChecked()){
        if(ui->checkBoxStructuredDataDetection->isChecked()){
            (*out).append(QByteArray("StructuredDataDetection true")+end);
        }else{
            (*out).append(QByteArray("StructuredDataDetection false")+end);
        }
    }
    if(ui->checkBoxEnableStructuredMinCreditCardCount->isChecked()){
        (*out).append(QByteArray("StructuredMinCreditCardCount ")+QString::number(ui->spinBoxStructuredMinCreditCardCount->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableStructuredMinSSNCount->isChecked()){
        (*out).append(QByteArray("StructuredMinSSNCount ")+QString::number(ui->spinBoxStructuredMinSSNCount->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableStructuredSSNFormatNormal->isChecked()){
        if(ui->checkBoxStructuredSSNFormatNormal->isChecked()){
            (*out).append(QByteArray("StructuredSSNFormatNormal yes")+end);
        }else{
            (*out).append(QByteArray("StructuredSSNFormatNormal no")+end);
        }
    }
    if(ui->checkBoxEnableStructuredSSNFormatStripped->isChecked()){
        if(ui->checkBoxStructuredSSNFormatStripped->isChecked()){
            (*out).append(QByteArray("StructuredSSNFormatStripped yes")+end);
        }else{
            (*out).append(QByteArray("StructuredSSNFormatStripped no")+end);
        }
    }
    if(ui->checkBoxEnableScanHTML->isChecked()){
        if(ui->checkBoxScanHTML->isChecked()){
            (*out).append(QByteArray("ScanHTML true")+end);
        }else{
            (*out).append(QByteArray("ScanHTML false")+end);
        }
    }
    if(ui->checkBoxEnableScanOLE2->isChecked()){
        if(ui->checkBoxScanOLE2->isChecked()){
            (*out).append(QByteArray("ScanOLE2 true")+end);
        }else{
            (*out).append(QByteArray("ScanOLE2 false")+end);
        }
    }
    if(ui->checkBoxEnableAlertBrokenExecutables->isChecked()){
        if(ui->checkBoxAlertBrokenExecutables->isChecked()){
            (*out).append(QByteArray("AlertBrokenExecutables yes")+end);
        }else{
            (*out).append(QByteArray("AlertBrokenExecutables no")+end);
        }
    }
    if(ui->checkBoxEnableAlertEncrypted->isChecked()){
        if(ui->checkBoxAlertEncrypted->isChecked()){
            (*out).append(QByteArray("AlertEncrypted yes")+end);
        }else{
            (*out).append(QByteArray("AlertEncrypted no")+end);
        }
    }
    if(ui->checkBoxEnableAlertEncryptedArchive->isChecked()){
        if(ui->checkBoxAlertEncryptedArchive->isChecked()){
            (*out).append(QByteArray("AlertEncryptedArchive yes")+end);
        }else{
            (*out).append(QByteArray("AlertEncryptedArchive no")+end);
        }
    }
    if(ui->checkBoxEnableAlertEncryptedDoc->isChecked()){
        if(ui->checkBoxAlertEncryptedDoc->isChecked()){
            (*out).append(QByteArray("AlertEncryptedDoc yes")+end);
        }else{
            (*out).append(QByteArray("AlertEncryptedDoc no")+end);
        }
    }
    if(ui->checkBoxEnableAlertOLE2Macros->isChecked()){
        if(ui->checkBoxAlertOLE2Macros->isChecked()){
            (*out).append(QByteArray("AlertOLE2Macros yes")+end);
        }else{
            (*out).append(QByteArray("AlertOLE2Macros no")+end);
        }
    }
    if(ui->checkBoxEnableAlertPhishingSSLMismatch->isChecked()){
        if(ui->checkBoxAlertPhishingSSLMismatch->isChecked()){
            (*out).append(QByteArray("AlertPhishingSSLMismatch yes")+end);
        }else{
            (*out).append(QByteArray("AlertPhishingSSLMismatch no")+end);
        }
    }
    if(ui->checkBoxEnableAlertPhishingCloak->isChecked()){
        if(ui->checkBoxAlertPhishingCloak->isChecked()){
            (*out).append(QByteArray("AlertPhishingCloak yes")+end);
        }else{
            (*out).append(QByteArray("AlertPhishingCloak no")+end);
        }
    }
    if(ui->checkBoxEnableAlertPartitionIntersection->isChecked()){
        if(ui->checkBoxAlertPartitionIntersection->isChecked()){
            (*out).append(QByteArray("AlertPartitionIntersection yes")+end);
        }else{
            (*out).append(QByteArray("AlertPartitionIntersection no")+end);
        }
    }
    if(ui->checkBoxEnableScanPDF->isChecked()){
        if(ui->checkBoxScanPDF->isChecked()){
            (*out).append(QByteArray("ScanPDF true")+end);
        }else{
            (*out).append(QByteArray("ScanPDF false")+end);
        }
    }
    if(ui->checkBoxEnableScanSWF->isChecked()){
        if(ui->checkBoxScanSWF->isChecked()){
            (*out).append(QByteArray("ScanSWF true")+end);
        }else{
            (*out).append(QByteArray("ScanSWF false")+end);
        }
    }
    if(ui->checkBoxEnableScanXMLDOCS->isChecked()){
        if(ui->checkBoxScanXMLDOCS->isChecked()){
            (*out).append(QByteArray("ScanXMLDOCS true")+end);
        }else{
            (*out).append(QByteArray("ScanXMLDOCS false")+end);
        }
    }
    if(ui->checkBoxEnableScanHWP3->isChecked()){
        if(ui->checkBoxScanHWP3->isChecked()){
            (*out).append(QByteArray("ScanHWP3 true")+end);
        }else{
            (*out).append(QByteArray("ScanHWP3 false")+end);
        }
    }
    if(ui->checkBoxEnableScanArchive->isChecked()){
        if(ui->checkBoxScanArchive->isChecked()){
            (*out).append(QByteArray("ScanArchive true")+end);
        }else{
            (*out).append(QByteArray("ScanArchive false")+end);
        }
    }
    if(ui->checkBoxEnableForceToDisk->isChecked()){
        if(ui->checkBoxForceToDisk->isChecked()){
            (*out).append(QByteArray("ForceToDisk true")+end);
        }else{
            (*out).append(QByteArray("ForceToDisk false")+end);
        }
    }
    if(ui->checkBoxEnableMaxScanTime->isChecked()){
        (*out).append(QByteArray("MaxScanTime ")+QString::number(ui->spinBoxMaxScanTime->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxScanSize->isChecked()){
        (*out).append(QByteArray("MaxScanSize ")+toClamInt(ui->spinBoxMaxScanSize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxFileSize->isChecked()){
        (*out).append(QByteArray("MaxFileSize ")+toClamInt(ui->spinBoxMaxFileSize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxRecursion->isChecked()){
        (*out).append(QByteArray("MaxRecursion ")+QString::number(ui->spinBoxMaxRecursion->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxFiles->isChecked()){
        (*out).append(QByteArray("MaxFiles ")+QString::number(ui->spinBoxMaxFiles->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxEmbeddedPE->isChecked()){
        (*out).append(QByteArray("MaxEmbeddedPE ")+toClamInt(ui->spinBoxMaxEmbeddedPE->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxHTMLNormalize->isChecked()){
        (*out).append(QByteArray("MaxHTMLNormalize ")+toClamInt(ui->spinBoxMaxHTMLNormalize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxHTMLNoTags->isChecked()){
        (*out).append(QByteArray("MaxHTMLNoTags ")+toClamInt(ui->spinBoxMaxHTMLNoTags->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxScriptNormalize->isChecked()){
        (*out).append(QByteArray("MaxScriptNormalize ")+toClamInt(ui->spinBoxMaxScriptNormalize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxZipTypeRcg->isChecked()){
        (*out).append(QByteArray("MaxZipTypeRcg ")+toClamInt(ui->spinBoxMaxZipTypeRcg->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxPartitions->isChecked()){
        (*out).append(QByteArray("MaxPartitions ")+QString::number(ui->spinBoxMaxPartitions->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxIconsPE->isChecked()){
        (*out).append(QByteArray("MaxIconsPE ")+QString::number(ui->spinBoxMaxIconsPE->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableMaxRecHWP3->isChecked()){
        (*out).append(QByteArray("MaxRecHWP3 ")+QString::number(ui->spinBoxMaxRecHWP3->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnablePCREMatchLimit->isChecked()){
        (*out).append(QByteArray("PCREMatchLimit ")+QString::number(ui->spinBoxPCREMatchLimit->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnablePCRERecMatchLimit->isChecked()){
        (*out).append(QByteArray("PCRERecMatchLimit ")+QString::number(ui->spinBoxPCRERecMatchLimit->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnablePCREMaxFileSize->isChecked()){
        (*out).append(QByteArray("PCREMaxFileSize ")+toClamInt(ui->spinBoxPCREMaxFileSize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableOnAccessMountPath->isChecked()){
        foreach(QString line, ui->stringListOnAccessMountPath->getQStringList()){
            (*out).append(QByteArray("OnAccessMountPath ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableOnAccessIncludePath->isChecked()){
        foreach(QString line, ui->stringListOnAccessIncludePath->getQStringList()){
            (*out).append(QByteArray("OnAccessIncludePath ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableOnAccessExcludePath->isChecked()){
        foreach(QString line, ui->stringListOnAccessExcludePath->getQStringList()){
            (*out).append(QByteArray("OnAccessExcludePath ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableOnAccessExcludeRootUID->isChecked()){
        if(ui->checkBoxOnAccessExcludeRootUID->isChecked()){
            (*out).append(QByteArray("OnAccessExcludeRootUID yes")+end);
        }else{
            (*out).append(QByteArray("OnAccessExcludeRootUID no")+end);
        }
    }
    if(ui->checkBoxEnableOnAccessExcludeUID->isChecked()){
        foreach(int line, ui->listSpinBoxOnAccessExcludeUID->getQListInt()){
            (*out).append(QByteArray("OnAccessExcludeUID ")+QByteArray::number(line)+end);
        }
    }
    if(ui->checkBoxEnableOnAccessExcludeUname->isChecked()){
        foreach(QString line, ui->stringListOnAccessExcludePath->getQStringList()){
            (*out).append(QByteArray("OnAccessExcludePath ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableOnAccessExcludeUname->isChecked()){
        foreach(QString line, ui->stringListOnAccessExcludeUname->getQStringList()){
            (*out).append(QByteArray("OnAccessExcludeUname ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableOnAccessMaxFileSize->isChecked()){
        (*out).append(QByteArray("OnAccessMaxFileSize ")+toClamInt(ui->spinBoxOnAccessMaxFileSize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableOnAccessDisableDDD->isChecked()){
        if(ui->checkBoxOnAccessDisableDDD->isChecked()){
            (*out).append(QByteArray("OnAccessDisableDDD yes")+end);
        }else{
            (*out).append(QByteArray("OnAccessDisableDDD no")+end);
        }
    }
    if(ui->checkBoxEnableOnAccessPrevention->isChecked()){
        if(ui->checkBoxOnAccessPrevention->isChecked()){
            (*out).append(QByteArray("OnAccessPrevention yes")+end);
        }else{
            (*out).append(QByteArray("OnAccessPrevention no")+end);
        }
    }
    if(ui->checkBoxEnableOnAccessExtraScanning->isChecked()){
        if(ui->checkBoxOnAccessExtraScanning->isChecked()){
            (*out).append(QByteArray("OnAccessExtraScanning yes")+end);
        }else{
            (*out).append(QByteArray("OnAccessExtraScanning no")+end);
        }
    }
    if(ui->checkBoxEnableOnAccessCurlTimeout->isChecked()){
        (*out).append(QByteArray("OnAccessCurlTimeout ")+QByteArray::number(ui->spinBoxOnAccessCurlTimeout->value())+end);
    }
    if(ui->checkBoxEnableOnAccessMaxThreads->isChecked()){
        (*out).append(QByteArray("OnAccessMaxThreads ")+QByteArray::number(ui->spinBoxOnAccessMaxThreads->value())+end);
    }
    if(ui->checkBoxEnableOnAccessRetryAttempts->isChecked()){
        (*out).append(QByteArray("OnAccessRetryAttempts ")+QByteArray::number(ui->spinBoxOnAccessRetryAttempts->value())+end);
    }
    if(ui->checkBoxEnableOnAccessDenyOnError->isChecked()){
        if(ui->checkBoxOnAccessDenyOnError->isChecked()){
            (*out).append(QByteArray("OnAccessDenyOnError yes")+end);
        }else{
            (*out).append(QByteArray("OnAccessDenyOnError no")+end);
        }
    }
    if(ui->checkBoxEnableDisableCertCheck->isChecked()){
        if(ui->checkBoxDisableCertCheck->isChecked()){
            (*out).append(QByteArray("DisableCertCheck true")+end);
        }else{
            (*out).append(QByteArray("DisableCertCheck false")+end);
        }
    }
#if 0
    if(ui->checkBoxEnableAlgorithmicDetection->isChecked()){
        if(ui->checkBoxAlgorithmicDetection->isChecked()){
            (*out).append(QByteArray("AlgorithmicDetection yes")+end);
        }else{
            (*out).append(QByteArray("AlgorithmicDetection no")+end);
        }
    }
    if(ui->checkBoxEnableBlockMax->isChecked()){
        if(ui->checkBoxBlockMax->isChecked()){
            (*out).append(QByteArray("BlockMax yes")+end);
        }else{
            (*out).append(QByteArray("BlockMax no")+end);
        }
    }
    if(ui->checkBoxEnablePhishingAlwaysBlockSSLMismatch->isChecked()){
        if(ui->checkBoxPhishingAlwaysBlockSSLMismatch->isChecked()){
            (*out).append(QByteArray("PhishingAlwaysBlockSSLMismatch yes")+end);
        }else{
            (*out).append(QByteArray("PhishingAlwaysBlockSSLMismatch no")+end);
        }
    }
    if(ui->checkBoxEnablePhishingAlwaysBlockCloak->isChecked()){
        if(ui->checkBoxPhishingAlwaysBlockCloak->isChecked()){
            (*out).append(QByteArray("PhishingAlwaysBlockCloak yes")+end);
        }else{
            (*out).append(QByteArray("PhishingAlwaysBlockCloak no")+end);
        }
    }
    if(ui->checkBoxEnablePartitionIntersection->isChecked()){
        if(ui->checkBoxPartitionIntersection->isChecked()){
            (*out).append(QByteArray("PartitionIntersection yes")+end);
        }else{
            (*out).append(QByteArray("PartitionIntersection no")+end);
        }
    }
    if(ui->checkBoxEnableOLE2BlockMacros->isChecked()){
        if(ui->checkBoxOLE2BlockMacros->isChecked()){
            (*out).append(QByteArray("OLE2BlockMacros yes")+end);
        }else{
            (*out).append(QByteArray("OLE2BlockMacros no")+end);
        }
    }
    if(ui->checkBoxEnableArchiveBlockEncrypted->isChecked()){
        if(ui->checkBoxArchiveBlockEncrypted->isChecked()){
            (*out).append(QByteArray("ArchiveBlockEncrypted yes")+end);
        }else{
            (*out).append(QByteArray("ArchiveBlockEncrypted no")+end);
        }
    }
#endif
    return true;
}

bool ConfigureDialogCurrent::fileUiToFreshclamconf(QByteArray *out){
    LINE_END
    (*out) = QByteArray();
    if(ui->checkBoxEnableFreshLogFileMaxSize->isChecked()){
        (*out).append(QByteArray("LogFileMaxSize ")+toClamInt(ui->spinBoxFreshLogFileMaxSize->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshLogTime->isChecked()){
        if(ui->checkBoxFreshLogTime->isChecked()){
            (*out).append(QByteArray("LogTime true")+end);
        }else{
            (*out).append(QByteArray("LogTime false")+end);
        }
    }
    if(ui->checkBoxEnableFreshLogSyslog->isChecked()){
        if(ui->checkBoxFreshLogSyslog->isChecked()){
            (*out).append(QByteArray("LogSyslog true")+end);
        }else{
            (*out).append(QByteArray("LogSyslog false")+end);
        }
    }
    if(ui->checkBoxEnableFreshLogFacility->isChecked()){
        (*out).append(QByteArray("LogFacility ")+ui->lineEditFreshLogFacility->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshLogVerbose->isChecked()){
        if(ui->checkBoxFreshLogVerbose->isChecked()){
            (*out).append(QByteArray("LogVerbose true")+end);
        }else{
            (*out).append(QByteArray("LogVerbose false")+end);
        }
    }
    if(ui->checkBoxEnableFreshLogRotate->isChecked()){
        if(ui->checkBoxFreshLogRotate->isChecked()){
            (*out).append(QByteArray("LogRotate true")+end);
        }else{
            (*out).append(QByteArray("LogRotate false")+end);
        }
    }
    if(ui->checkBoxEnableFreshPidFile->isChecked()){
        (*out).append(QByteArray("PidFile ")+ui->lineEditFreshPidFile->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshDatabaseDirectory->isChecked()){
        (*out).append(QByteArray("DatabaseDirectory ")+ui->lineEditFreshDatabaseDirectory->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshForeground->isChecked()){
        if(ui->checkBoxFreshForeground->isChecked()){
            (*out).append(QByteArray("Foreground true")+end);
        }else{
            (*out).append(QByteArray("Foreground false")+end);
        }
    }
    if(ui->checkBoxEnableFreshDebug->isChecked()){
        if(ui->checkBoxFreshDebug->isChecked()){
            (*out).append(QByteArray("Debug true")+end);
        }else{
            (*out).append(QByteArray("Debug false")+end);
        }
    }
    if(ui->checkBoxEnableFreshUpdateLogFile->isChecked()){
        (*out).append(QByteArray("UpdateLogFile ")+ui->lineEditFreshUpdateLogFile->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshDatabaseOwner->isChecked()){
        (*out).append(QByteArray("DatabaseOwner ")+ui->lineEditFreshDatabaseOwner->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshChecks->isChecked()){
        (*out).append(QByteArray("Checks ")+QString::number(ui->spinBoxFreshChecks->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshDNSDatabaseInfo->isChecked()){
        (*out).append(QByteArray("DNSDatabaseInfo ")+ui->lineEditFreshDNSDatabaseInfo->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshDatabaseMirror->isChecked()){
        foreach(QString line, ui->stringListFreshDatabaseMirror->getQStringList()){
            (*out).append(QByteArray("DatabaseMirror ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableFreshPrivateMirror->isChecked()){
        foreach(QString line, ui->stringListFreshPrivateMirror->getQStringList()){
            (*out).append(QByteArray("PrivateMirror ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableFreshMaxAttempts->isChecked()){
        (*out).append(QByteArray("MaxAttempts ")+QString::number(ui->spinBoxFreshMaxAttempts->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshScriptedUpdates->isChecked()){
        if(ui->checkBoxFreshScriptedUpdates->isChecked()){
            (*out).append(QByteArray("ScriptedUpdates yes")+end);
        }else{
            (*out).append(QByteArray("ScriptedUpdates no")+end);
        }
    }
    if(ui->checkBoxEnableFreshTestDatabases->isChecked()){
        if(ui->checkBoxFreshTestDatabases->isChecked()){
            (*out).append(QByteArray("TestDatabases yes")+end);
        }else{
            (*out).append(QByteArray("TestDatabases no")+end);
        }
    }
    if(ui->checkBoxEnableFreshCompressLocalDatabase->isChecked()){
        if(ui->checkBoxFreshCompressLocalDatabase->isChecked()){
            (*out).append(QByteArray("CompressLocalDatabase yes")+end);
        }else{
            (*out).append(QByteArray("CompressLocalDatabase no")+end);
        }
    }
    if(ui->checkBoxEnableFreshExtraDatabase->isChecked()){
        foreach(QString line, ui->stringListFreshExtraDatabase->getQStringList()){
            (*out).append(QByteArray("ExtraDatabase ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableFreshExcludeDatabase->isChecked()){
        foreach(QString line, ui->stringListFreshExcludeDatabase->getQStringList()){
            (*out).append(QByteArray("ExcludeDatabase ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableFreshDatabaseCustomURL->isChecked()){
        foreach(QString line, ui->stringListFreshDatabaseCustomURL->getQStringList()){
            (*out).append(QByteArray("DatabaseCustomURL ")+line.toLocal8Bit()+end);
        }
    }
    if(ui->checkBoxEnableFreshHTTPProxyServer->isChecked()){
        (*out).append(QByteArray("HTTPProxyServer ")+ui->lineEditFreshHTTPProxyServer->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshHTTPProxyPort->isChecked()){
        (*out).append(QByteArray("HTTPProxyPort ")+QString::number(ui->spinBoxFreshHTTPProxyPort->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshHTTPProxyUsername->isChecked()){
        (*out).append(QByteArray("HTTPProxyUsername ")+ui->lineEditFreshHTTPProxyUsername->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshHTTPProxyPassword->isChecked()){
        (*out).append(QByteArray("HTTPProxyPassword ")+ui->lineEditFreshHTTPProxyPassword->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshHTTPUserAgent->isChecked()){
        (*out).append(QByteArray("HTTPUserAgent ")+ui->lineEditFreshHTTPUserAgent->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshNotifyClamd->isChecked()){
        (*out).append(QByteArray("NotifyClamd ")+ui->lineEditFreshNotifyClamd->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshOnUpdateExecute->isChecked()){
        (*out).append(QByteArray("OnUpdateExecute ")+ui->lineEditFreshOnUpdateExecute->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshOnErrorExecute->isChecked()){
        (*out).append(QByteArray("OnErrorExecute ")+ui->lineEditFreshOnErrorExecute->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshOnOutdatedExecute->isChecked()){
        (*out).append(QByteArray("OnOutdatedExecute ")+ui->lineEditFreshOnOutdatedExecute->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshLocalIPAddress->isChecked()){
        (*out).append(QByteArray("LocalIPAddress ")+ui->lineEditFreshLocalIPAddress->text().toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshConnectTimeout->isChecked()){
        (*out).append(QByteArray("ConnectTimeout ")+QString::number(ui->spinBoxFreshConnectTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshReceiveTimeout->isChecked()){
        (*out).append(QByteArray("ReceiveTimeout ")+QString::number(ui->spinBoxFreshReceiveTimeout->value()).toLocal8Bit()+end);
    }
    if(ui->checkBoxEnableFreshSafeBrowsing->isChecked()){
        if(ui->checkBoxFreshSafeBrowsing->isChecked()){
            (*out).append(QByteArray("SafeBrowsing true")+end);
        }else{
            (*out).append(QByteArray("SafeBrowsing false")+end);
        }
    }
    if(ui->checkBoxEnableFreshBytecode->isChecked()){
        if(ui->checkBoxFreshBytecode->isChecked()){
            (*out).append(QByteArray("Bytecode true")+end);
        }else{
            (*out).append(QByteArray("Bytecode false")+end);
        }
    }
    return true;
}

int ConfigureDialogCurrent::toClamInt(QString in){
    if(in[in.length()-1] == "k" || in[in.length()-1] == "K"){
        bool ok = false;
        int base = in.mid(0, in.length()-1).toInt(&ok);
        if(!ok)
            return -1;
        return base*1000;
    }else if(in[in.length()-1] == "m" || in[in.length()-1] == "M"){
        bool ok = false;
        int base = in.mid(0, in.length()-1).toInt(&ok);
        if(!ok)
            return -1;
        return base*1000000;
    }else if(in[in.length()-1] == "L"){
        bool ok = false;
        int base = in.mid(0, in.length()-1).toInt(&ok);
        if(!ok)
            return -1;
        return base;
    }
    bool ok = false;
    int base = in.toInt(&ok);
    if(ok)
        return base;

    return -1;
}

QString ConfigureDialogCurrent::toClamInt(int in){
    if(in < 0)
        return QString();
    if(!(in % 1000000) && in >= 1000000){
        int ret = in / 1000000;
        return QString::number(ret)+tr("M");
    }else if(!(in % 1000) && in >= 1000){
        int ret = in / 1000;
        return QString::number(ret)+tr("K");
    }
    return QString::number(in);
}

bool ConfigureDialogCurrent::matchBoolTrue(QRegularExpression r, QByteArray l){
    return r.match(l).captured("varname").toLower() == QString("true") ||
            r.match(l).captured("varname").toLower() == QString("yes");
}

bool ConfigureDialogCurrent::matchBoolFalse(QRegularExpression r, QByteArray l){
    return r.match(l).captured("varname").toLower() == QString("false") ||
            r.match(l).captured("varname").toLower() == QString("no");
}

void ConfigureDialogCurrent::on_pushButtonReloadClamav_clicked(){
    QMessageBox msgBox;
    msgBox.setText("Would you like to reload both Clamd and Freshclam, and run their respective updated configuration files?");
    msgBox.setInformativeText("Reload?");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    int ret = msgBox.exec();
    if(ret == QMessageBox::Yes){
        QProcess *p = new QProcess();
        p->start("pkexec", QStringList() << "bash" << "-c" << "service clamav-freshclam restart; service clamav-daemon restart");
        if (!p->waitForStarted())
                return;
        if (!p->waitForFinished())
                return;
    }
}

void ConfigureDialogCurrent::on_pushButtonApply_clicked(){
    bool sendReload = false;
    emit setValDB("clamdconf", ui->lineEditLocationOfClamdconf->text());
    emit setValDB("freshclamconf", ui->lineEditLocationOfFreshclamconf->text());
    emit setValDB("entriesperpage", QString::number(ui->spinBoxEntriesPerPage->value()));
    emit setValDB("monitoronaccess", (ui->checkBoxMonitorOnAccess->isChecked())?"yes":"no");
    emit setValDB("enablequarantine", (ui->checkBoxEnableClamOneQuarantine->isChecked())?"yes":"no");
    emit setValDB("maxquarantinesize", QString::number(ui->spinBoxMaximumFileSizeToQuarantine->value()));
    emit setValDB("quarantinefilesdirectory", ui->lineEditLocationOfQuarantineFilesDirectory->text());
    emit refreshEventGeneral(0);
    emit refreshEventFound(0, true);
    emit refreshEventQuarantined(0);
    emit refreshMessages(0);
    emit refreshQuarantineDirectory();
    emit setEnabledQuarantine(ui->checkBoxEnableClamOneQuarantine->isChecked());
    QByteArray newClamdconf;
    fileUiToClamdconf(&newClamdconf);
    if(oldClamdconf != newClamdconf){
        //Write new file somehow, needs elivated permissions.
        QFile f(ui->lineEditLocationOfClamdconf->text());
        if(f.open(QFile::WriteOnly|QFile::Truncate)){
            f.write(newClamdconf);
            f.write(oldErrClamdconf);
            f.flush();
            f.close();
            sendReload = true;
        }else{
            QProcess *p = new QProcess();
            p->start("pkexec", QStringList() << "tee" << ui->lineEditLocationOfClamdconf->text());
            if (!p->waitForStarted())
                    return;
            p->write(newClamdconf, newClamdconf.length());
            p->write(oldErrClamdconf, oldErrClamdconf.length());
            p->closeWriteChannel();
            if (!p->waitForFinished())
                    return;
            sendReload = true;
        }
        fileClamdconfToUI(ui->lineEditLocationOfClamdconf->text());
    }
    QByteArray newFreshclamconf;
    fileUiToFreshclamconf(&newFreshclamconf);
    if(oldFreshclamconf != newFreshclamconf){
        //Write new file somehow, needs elivated permissions.
        QFile f(ui->lineEditLocationOfFreshclamconf->text());
        if(f.open(QFile::WriteOnly|QFile::Truncate)){
            f.write(newFreshclamconf);
            f.write(oldErrFreshclamconf);
            f.flush();
            f.close();
            sendReload = true;
        }else{
            QProcess *p = new QProcess();
            p->start("pkexec", QStringList() << "tee" << ui->lineEditLocationOfFreshclamconf->text());
            if (!p->waitForStarted())
                    return;
            p->write(newFreshclamconf, newFreshclamconf.length());
            p->write(oldErrFreshclamconf, oldErrFreshclamconf.length());
            p->closeWriteChannel();
            if (!p->waitForFinished())
                    return;
            sendReload = true;
        }
        fileFreshclamconfToUI(ui->lineEditLocationOfFreshclamconf->text());
    }
    if(sendReload){
        on_pushButtonReloadClamav_clicked();
    }
}

void ConfigureDialogCurrent::on_pushButtonOk_clicked(){
    on_pushButtonApply_clicked();
    on_pushButtonCancel_clicked();
}

void ConfigureDialogCurrent::on_pushButtonCancel_clicked(){
    ui->lineEditLocationOfClamdconf->setText("");
    ui->lineEditLocationOfFreshclamconf->setText("");
    ui->spinBoxEntriesPerPage->setValue(40);
    ui->checkBoxMonitorOnAccess->setChecked(false);
    ui->checkBoxEnableClamOneQuarantine->setChecked(false);
    ui->tabWidgetClamd->setCurrentIndex(0);
    ui->tabWidgetFreshclam->setCurrentIndex(0);
    ui->listWidgetMain->setCurrentRow(0);
    oldClamdconf = QByteArray();
    oldErrClamdconf = QByteArray();
    oldFreshclamconf = QByteArray();
    oldErrFreshclamconf = QByteArray();
    hide();
}

void ConfigureDialogCurrent::on_pushButtonClamconfFileDialog_clicked(){
    QString fileName = QFileDialog::getOpenFileName(this,
            tr("Open Configuration File"), QFileInfo(ui->lineEditLocationOfClamdconf->text()).baseName(),
            tr("Conf Files (*.conf);;All Files (*)"));
    if(!fileName.isEmpty() && QFile(fileName).exists()){
        ui->lineEditLocationOfClamdconf->setText(fileName);
    }
}

void ConfigureDialogCurrent::on_pushButtonFreshclamconfFileDialog_clicked(){
    QString fileName = QFileDialog::getOpenFileName(this,
            tr("Open Configuration File"), QFileInfo(ui->lineEditLocationOfFreshclamconf->text()).baseName(),
            tr("Conf Files (*.conf);;All Files (*)"));
    if(!fileName.isEmpty() && QFile(fileName).exists()){
        ui->lineEditLocationOfFreshclamconf->setText(fileName);
    }
}


void ConfigureDialogCurrent::disableAllClamdconf(){
    //clamd.conf
    ui->checkBoxEnableLocalSocket->setChecked(false);
    ui->checkBoxEnableLocalSocketGroup->setChecked(false);
    ui->checkBoxEnableLocalSocketMode->setChecked(false);
    ui->checkBoxEnableFixStaleSocket->setChecked(false);
    ui->checkBoxEnableTCPSocket->setChecked(false);
    ui->checkBoxEnableTCPAddr->setChecked(false);
    ui->checkBoxEnableMaxConnectionQueueLength->setChecked(false);
    ui->checkBoxEnableStreamMaxLength->setChecked(false);
    ui->checkBoxEnableStreamMinPort->setChecked(false);
    ui->checkBoxEnableStreamMaxPort->setChecked(false);
    ui->checkBoxEnableMaxThreads->setChecked(false);
    ui->checkBoxEnableReadTimeout->setChecked(false);
    ui->checkBoxEnableCommandReadTimeout->setChecked(false);
    ui->checkBoxEnableSendBufTimeout->setChecked(false);
    ui->checkBoxEnableMaxQueue->setChecked(false);
    ui->checkBoxEnableIdleTimeout->setChecked(false);
    ui->checkBoxEnableExcludePath->setChecked(false);
    ui->checkBoxEnableLogFile->setChecked(false);
    ui->checkBoxEnableLogFileUnlock->setChecked(false);
    ui->checkBoxEnableLogFileMaxSize->setChecked(false);
    ui->checkBoxEnableLogTime->setChecked(false);
    ui->checkBoxEnableLogClean->setChecked(false);
    ui->checkBoxEnableLogSyslog->setChecked(false);
    ui->checkBoxEnableLogFacility->setChecked(false);
    ui->checkBoxEnableLogVerbose->setChecked(false);
    ui->checkBoxEnableLogRotate->setChecked(false);
    ui->checkBoxEnableExtendedDetectionInfo->setChecked(false);
    ui->checkBoxEnablePidFile->setChecked(false);
    ui->checkBoxEnableTemporaryDirectory->setChecked(false);
    ui->checkBoxEnableDatabaseDirectory->setChecked(false);
    ui->checkBoxEnableOfficialDatabaseOnly->setChecked(false);
    ui->checkBoxEnableMaxDirectoryRecursion->setChecked(false);
    ui->checkBoxEnableFollowDirectorySymlinks->setChecked(false);
    ui->checkBoxEnableFollowFileSymlinks->setChecked(false);
    ui->checkBoxEnableCrossFilesystems->setChecked(false);
    ui->checkBoxEnableSelfCheck->setChecked(false);
    ui->checkBoxEnableDisableCache->setChecked(false);
    ui->checkBoxEnableVirusEvent->setChecked(false);
    ui->checkBoxEnableExitOnOOM->setChecked(false);
    ui->checkBoxEnableAllowAllMatchScan->setChecked(false);
    ui->checkBoxEnableForeground->setChecked(false);
    ui->checkBoxEnableDebug->setChecked(false);
    ui->checkBoxEnableLeaveTemporaryFiles->setChecked(false);
    ui->checkBoxEnableUser->setChecked(false);
    ui->checkBoxEnableBytecode->setChecked(false);
    ui->checkBoxEnableBytecodeSecurity->setChecked(false);
    ui->checkBoxEnableBytecodeTimeout->setChecked(false);
    ui->checkBoxEnableBytecodeUnsigned->setChecked(false);
    ui->checkBoxEnableBytecodeMode->setChecked(false);
    ui->checkBoxEnableDetectPUA->setChecked(false);
    ui->checkBoxEnableExcludePUA->setChecked(false);
    ui->checkBoxEnableIncludePUA->setChecked(false);
    ui->checkBoxEnableScanPE->setChecked(false);
    ui->checkBoxEnableScanELF->setChecked(false);
    ui->checkBoxEnableScanMail->setChecked(false);
    ui->checkBoxEnableScanPartialMessages->setChecked(false);
    ui->checkBoxEnablePhishingSignatures->setChecked(false);
    ui->checkBoxEnablePhishingScanURLs->setChecked(false);
    ui->checkBoxEnableHeuristicAlerts->setChecked(false);
    ui->checkBoxEnableHeuristicScanPrecedence->setChecked(false);
    ui->checkBoxEnableStructuredDataDetection->setChecked(false);
    ui->checkBoxEnableStructuredMinCreditCardCount->setChecked(false);
    ui->checkBoxEnableStructuredMinSSNCount->setChecked(false);
    ui->checkBoxEnableStructuredSSNFormatNormal->setChecked(false);
    ui->checkBoxEnableStructuredSSNFormatStripped->setChecked(false);
    ui->checkBoxEnableScanHTML->setChecked(false);
    ui->checkBoxEnableScanOLE2->setChecked(false);
    ui->checkBoxEnableScanPDF->setChecked(false);
    ui->checkBoxEnableScanSWF->setChecked(false);
    ui->checkBoxEnableScanXMLDOCS->setChecked(false);
    ui->checkBoxEnableScanHWP3->setChecked(false);
    ui->checkBoxEnableScanArchive->setChecked(false);
    ui->checkBoxEnableAlertBrokenExecutables->setChecked(false);
    ui->checkBoxEnableAlertEncrypted->setChecked(false);
    ui->checkBoxEnableAlertEncryptedArchive->setChecked(false);
    ui->checkBoxEnableAlertEncryptedDoc->setChecked(false);
    ui->checkBoxEnableAlertOLE2Macros->setChecked(false);
    ui->checkBoxEnableAlertExceedsMax->setChecked(false);
    ui->checkBoxEnableAlertPhishingSSLMismatch->setChecked(false);
    ui->checkBoxEnableAlertPhishingCloak->setChecked(false);
    ui->checkBoxEnableAlertPartitionIntersection->setChecked(false);
    ui->checkBoxEnableForceToDisk->setChecked(false);
    ui->checkBoxEnableMaxScanTime->setChecked(false);
    ui->checkBoxEnableMaxScanSize->setChecked(false);
    ui->checkBoxEnableMaxFileSize->setChecked(false);
    ui->checkBoxEnableMaxRecursion->setChecked(false);
    ui->checkBoxEnableMaxFiles->setChecked(false);
    ui->checkBoxEnableMaxEmbeddedPE->setChecked(false);
    ui->checkBoxEnableMaxHTMLNormalize->setChecked(false);
    ui->checkBoxEnableMaxHTMLNoTags->setChecked(false);
    ui->checkBoxEnableMaxScriptNormalize->setChecked(false);
    ui->checkBoxEnableMaxZipTypeRcg->setChecked(false);
    ui->checkBoxEnableMaxPartitions->setChecked(false);
    ui->checkBoxEnableMaxIconsPE->setChecked(false);
    ui->checkBoxEnableMaxRecHWP3->setChecked(false);
    ui->checkBoxEnablePCREMatchLimit->setChecked(false);
    ui->checkBoxEnablePCRERecMatchLimit->setChecked(false);
    ui->checkBoxEnablePCREMaxFileSize->setChecked(false);
    ui->checkBoxEnableOnAccessMountPath->setChecked(false);
    ui->checkBoxEnableOnAccessIncludePath->setChecked(false);
    ui->checkBoxEnableOnAccessExcludePath->setChecked(false);
    ui->checkBoxEnableOnAccessExcludeRootUID->setChecked(false);
    ui->checkBoxEnableOnAccessExcludeUID->setChecked(false);
    ui->checkBoxEnableOnAccessExcludeUname->setChecked(false);
    ui->checkBoxEnableOnAccessMaxFileSize->setChecked(false);
    ui->checkBoxEnableOnAccessDisableDDD->setChecked(false);
    ui->checkBoxEnableOnAccessPrevention->setChecked(false);
    ui->checkBoxEnableOnAccessExtraScanning->setChecked(false);
    ui->checkBoxEnableOnAccessCurlTimeout->setChecked(false);
    ui->checkBoxEnableOnAccessMaxThreads->setChecked(false);
    ui->checkBoxEnableOnAccessRetryAttempts->setChecked(false);
    ui->checkBoxEnableOnAccessDenyOnError->setChecked(false);
    ui->checkBoxEnableDisableCertCheck->setChecked(false);
    ui->checkBoxEnablePreludeEnable->setChecked(false);
    ui->checkBoxEnableScanOnAccess->setChecked(false);
}

void ConfigureDialogCurrent::disableAllFreshclamconf(){
    //freshclam.conf
    ui->checkBoxEnableFreshLogFileMaxSize->setChecked(false);
    ui->checkBoxEnableFreshLogTime->setChecked(false);
    ui->checkBoxEnableFreshLogSyslog->setChecked(false);
    ui->checkBoxEnableFreshLogFacility->setChecked(false);
    ui->checkBoxEnableFreshLogVerbose->setChecked(false);
    ui->checkBoxEnableFreshLogRotate->setChecked(false);
    ui->checkBoxEnableFreshPidFile->setChecked(false);
    ui->checkBoxEnableFreshDatabaseDirectory->setChecked(false);
    ui->checkBoxEnableFreshForeground->setChecked(false);
    ui->checkBoxEnableFreshDebug->setChecked(false);
    ui->checkBoxEnableFreshUpdateLogFile->setChecked(false);
    ui->checkBoxEnableFreshDatabaseOwner->setChecked(false);
    ui->checkBoxEnableFreshChecks->setChecked(false);
    ui->checkBoxEnableFreshDNSDatabaseInfo->setChecked(false);
    ui->checkBoxEnableFreshDatabaseMirror->setChecked(false);
    ui->checkBoxEnableFreshPrivateMirror->setChecked(false);
    ui->checkBoxEnableFreshMaxAttempts->setChecked(false);
    ui->checkBoxEnableFreshScriptedUpdates->setChecked(false);
    ui->checkBoxEnableFreshTestDatabases->setChecked(false);
    ui->checkBoxEnableFreshCompressLocalDatabase->setChecked(false);
    ui->checkBoxEnableFreshExtraDatabase->setChecked(false);
    ui->checkBoxEnableFreshExcludeDatabase->setChecked(false);
    ui->checkBoxEnableFreshDatabaseCustomURL->setChecked(false);
    ui->checkBoxEnableFreshHTTPProxyServer->setChecked(false);
    ui->checkBoxEnableFreshHTTPProxyPort->setChecked(false);
    ui->checkBoxEnableFreshHTTPProxyUsername->setChecked(false);
    ui->checkBoxEnableFreshHTTPProxyPassword->setChecked(false);
    ui->checkBoxEnableFreshHTTPUserAgent->setChecked(false);
    ui->checkBoxEnableFreshNotifyClamd->setChecked(false);
    ui->checkBoxEnableFreshOnUpdateExecute->setChecked(false);
    ui->checkBoxEnableFreshOnErrorExecute->setChecked(false);
    ui->checkBoxEnableFreshOnOutdatedExecute->setChecked(false);
    ui->checkBoxEnableFreshLocalIPAddress->setChecked(false);
    ui->checkBoxEnableFreshConnectTimeout->setChecked(false);
    ui->checkBoxEnableFreshReceiveTimeout->setChecked(false);
    ui->checkBoxEnableFreshSafeBrowsing->setChecked(false);
    ui->checkBoxEnableFreshBytecode->setChecked(false);
}

void ConfigureDialogCurrent::on_checkBoxPreludeEnable_stateChanged(int state){
    if(state){
        ui->checkBoxPreludeEnable->setText(tr("yes"));
        ui->labelPreludeAnalyzerName->setEnabled(true);
        ui->lineEditPreludeAnalyzerName->setEnabled(true);
    }else{
        ui->checkBoxPreludeEnable->setText(tr("no"));
        ui->labelPreludeAnalyzerName->setEnabled(false);
        ui->lineEditPreludeAnalyzerName->setEnabled(false);
    }
}

void ConfigureDialogCurrent::on_checkBoxLogFileUnlock_stateChanged(int state){
    if(state)
        ui->checkBoxLogFileUnlock->setText(tr("yes"));
    else
        ui->checkBoxLogFileUnlock->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxLogTime_stateChanged(int state){
    if(state)
        ui->checkBoxLogTime->setText(tr("yes"));
    else
        ui->checkBoxLogTime->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxLogClean_stateChanged(int state){
    if(state)
        ui->checkBoxLogClean->setText(tr("yes"));
    else
        ui->checkBoxLogClean->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxLogSyslog_stateChanged(int state){
    if(state)
        ui->checkBoxLogSyslog->setText(tr("yes"));
    else
        ui->checkBoxLogSyslog->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxLogVerbose_stateChanged(int state){
    if(state)
        ui->checkBoxLogVerbose->setText(tr("yes"));
    else
        ui->checkBoxLogVerbose->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxLogRotate_stateChanged(int state){
    if(state)
        ui->checkBoxLogRotate->setText(tr("yes"));
    else
        ui->checkBoxLogRotate->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxExtendedDetectionInfo_stateChanged(int state){
    if(state)
        ui->checkBoxExtendedDetectionInfo->setText(tr("yes"));
    else
        ui->checkBoxExtendedDetectionInfo->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxOfficialDatabaseOnly_stateChanged(int state){
    if(state)
        ui->checkBoxOfficialDatabaseOnly->setText(tr("yes"));
    else
        ui->checkBoxOfficialDatabaseOnly->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFixStaleSocket_stateChanged(int state){
    if(state)
        ui->checkBoxFixStaleSocket->setText(tr("yes"));
    else
        ui->checkBoxFixStaleSocket->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFollowDirectorySymlinks_stateChanged(int state){
    if(state)
        ui->checkBoxFollowDirectorySymlinks->setText(tr("yes"));
    else
        ui->checkBoxFollowDirectorySymlinks->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFollowFileSymlinks_stateChanged(int state){
    if(state)
        ui->checkBoxFollowFileSymlinks->setText(tr("yes"));
    else
        ui->checkBoxFollowFileSymlinks->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxCrossFilesystems_stateChanged(int state){
    if(state)
        ui->checkBoxCrossFilesystems->setText(tr("yes"));
    else
        ui->checkBoxCrossFilesystems->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxDisableCache_stateChanged(int state){
    if(state)
        ui->checkBoxDisableCache->setText(tr("yes"));
    else
        ui->checkBoxDisableCache->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxExitOnOOM_stateChanged(int state){
    if(state)
        ui->checkBoxExitOnOOM->setText(tr("yes"));
    else
        ui->checkBoxExitOnOOM->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAllowAllMatchScan_stateChanged(int state){
    if(state)
        ui->checkBoxAllowAllMatchScan->setText(tr("yes"));
    else
        ui->checkBoxAllowAllMatchScan->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxForeground_stateChanged(int state){
    if(state)
        ui->checkBoxForeground->setText(tr("yes"));
    else
        ui->checkBoxForeground->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxDebug_stateChanged(int state){
    if(state)
        ui->checkBoxDebug->setText(tr("yes"));
    else
        ui->checkBoxDebug->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxLeaveTemporaryFiles_stateChanged(int state){
    if(state)
        ui->checkBoxLeaveTemporaryFiles->setText(tr("yes"));
    else
        ui->checkBoxLeaveTemporaryFiles->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxBytecode_stateChanged(int state){
    if(state)
        ui->checkBoxBytecode->setText(tr("yes"));
    else
        ui->checkBoxBytecode->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxBytecodeUnsigned_stateChanged(int state){
    if(state)
        ui->checkBoxBytecodeUnsigned->setText(tr("yes"));
    else
        ui->checkBoxBytecodeUnsigned->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxDetectPUA_stateChanged(int state){
    if(state)
        ui->checkBoxDetectPUA->setText(tr("yes"));
    else
        ui->checkBoxDetectPUA->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanPE_stateChanged(int state){
    if(state)
        ui->checkBoxScanPE->setText(tr("yes"));
    else
        ui->checkBoxScanPE->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanELF_stateChanged(int state){
    if(state)
        ui->checkBoxScanELF->setText(tr("yes"));
    else
        ui->checkBoxScanELF->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanMail_stateChanged(int state){
    if(state)
        ui->checkBoxScanMail->setText(tr("yes"));
    else
        ui->checkBoxScanMail->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanPartialMessages_stateChanged(int state){
    if(state)
        ui->checkBoxScanPartialMessages->setText(tr("yes"));
    else
        ui->checkBoxScanPartialMessages->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxPhishingSignatures_stateChanged(int state){
    if(state)
        ui->checkBoxPhishingSignatures->setText(tr("yes"));
    else
        ui->checkBoxPhishingSignatures->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxPhishingScanURLs_stateChanged(int state){
    if(state)
        ui->checkBoxPhishingScanURLs->setText(tr("yes"));
    else
        ui->checkBoxPhishingScanURLs->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxHeuristicAlerts_stateChanged(int state){
    if(state)
        ui->checkBoxHeuristicAlerts->setText(tr("yes"));
    else
        ui->checkBoxHeuristicAlerts->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxHeuristicScanPrecedence_stateChanged(int state){
    if(state)
        ui->checkBoxHeuristicScanPrecedence->setText(tr("yes"));
    else
        ui->checkBoxHeuristicScanPrecedence->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxStructuredDataDetection_stateChanged(int state){
    if(state)
        ui->checkBoxStructuredDataDetection->setText(tr("yes"));
    else
        ui->checkBoxStructuredDataDetection->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxStructuredSSNFormatNormal_stateChanged(int state){
    if(state)
        ui->checkBoxStructuredSSNFormatNormal->setText(tr("yes"));
    else
        ui->checkBoxStructuredSSNFormatNormal->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxStructuredSSNFormatStripped_stateChanged(int state){
    if(state)
        ui->checkBoxStructuredSSNFormatStripped->setText(tr("yes"));
    else
        ui->checkBoxStructuredSSNFormatStripped->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanHTML_stateChanged(int state){
    if(state)
        ui->checkBoxScanHTML->setText(tr("yes"));
    else
        ui->checkBoxScanHTML->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanOLE2_stateChanged(int state){
    if(state)
        ui->checkBoxScanOLE2->setText(tr("yes"));
    else
        ui->checkBoxScanOLE2->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertEncrypted_stateChanged(int state){
    if(state)
        ui->checkBoxAlertEncrypted->setText(tr("yes"));
    else
        ui->checkBoxAlertEncrypted->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertEncryptedArchive_stateChanged(int state){
    if(state)
        ui->checkBoxAlertEncryptedArchive->setText(tr("yes"));
    else
        ui->checkBoxAlertEncryptedArchive->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertEncryptedDoc_stateChanged(int state){
    if(state)
        ui->checkBoxAlertEncryptedDoc->setText(tr("yes"));
    else
        ui->checkBoxAlertEncryptedDoc->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertOLE2Macros_stateChanged(int state){
    if(state)
        ui->checkBoxAlertOLE2Macros->setText(tr("yes"));
    else
        ui->checkBoxAlertOLE2Macros->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertExceedsMax_stateChanged(int state){
    if(state)
        ui->checkBoxAlertExceedsMax->setText(tr("yes"));
    else
        ui->checkBoxAlertExceedsMax->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertPhishingSSLMismatch_stateChanged(int state){
    if(state)
        ui->checkBoxAlertOLE2Macros->setText(tr("yes"));
    else
        ui->checkBoxAlertOLE2Macros->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertPhishingCloak_stateChanged(int state){
    if(state)
        ui->checkBoxAlertPhishingCloak->setText(tr("yes"));
    else
        ui->checkBoxAlertPhishingCloak->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxAlertPartitionIntersection_stateChanged(int state){
    if(state)
        ui->checkBoxAlertPartitionIntersection->setText(tr("yes"));
    else
        ui->checkBoxAlertPartitionIntersection->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanPDF_stateChanged(int state){
    if(state)
        ui->checkBoxScanPDF->setText(tr("yes"));
    else
        ui->checkBoxScanPDF->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanSWF_stateChanged(int state){
    if(state)
        ui->checkBoxScanSWF->setText(tr("yes"));
    else
        ui->checkBoxScanSWF->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanXMLDOCS_stateChanged(int state){
    if(state)
        ui->checkBoxScanXMLDOCS->setText(tr("yes"));
    else
        ui->checkBoxScanXMLDOCS->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanArchive_stateChanged(int state){
    if(state)
        ui->checkBoxScanArchive->setText(tr("yes"));
    else
        ui->checkBoxScanArchive->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxOnAccessExcludeRootUID_stateChanged(int state){
    if(state)
        ui->checkBoxOnAccessExcludeRootUID->setText(tr("yes"));
    else
        ui->checkBoxOnAccessExcludeRootUID->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxOnAccessDisableDDD_stateChanged(int state){
    if(state)
        ui->checkBoxOnAccessDisableDDD->setText(tr("yes"));
    else
        ui->checkBoxOnAccessDisableDDD->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxOnAccessPrevention_stateChanged(int state){
    if(state)
        ui->checkBoxOnAccessPrevention->setText(tr("yes"));
    else
        ui->checkBoxOnAccessPrevention->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxOnAccessExtraScanning_stateChanged(int state){
    if(state)
        ui->checkBoxOnAccessExtraScanning->setText(tr("yes"));
    else
        ui->checkBoxOnAccessExtraScanning->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxOnAccessDenyOnError_stateChanged(int state){
    if(state)
        ui->checkBoxOnAccessDenyOnError->setText(tr("yes"));
    else
        ui->checkBoxOnAccessDenyOnError->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxDisableCertCheck_stateChanged(int state){
    if(state)
        ui->checkBoxDisableCertCheck->setText(tr("yes"));
    else
        ui->checkBoxDisableCertCheck->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxScanOnAccess_stateChanged(int state){
    if(state)
        ui->checkBoxScanOnAccess->setText(tr("yes"));
    else
        ui->checkBoxScanOnAccess->setText(tr("no"));
}

//Options
void ConfigureDialogCurrent::on_checkBoxMonitorOnAccess_stateChanged(int state){
    if(state)
        ui->checkBoxMonitorOnAccess->setText(tr("yes"));
    else
        ui->checkBoxMonitorOnAccess->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxEnableClamOneQuarantine_stateChanged(int state){
    if(state)
        ui->checkBoxEnableClamOneQuarantine->setText(tr("yes"));
    else
        ui->checkBoxEnableClamOneQuarantine->setText(tr("no"));
}

//Freshclam.conf
void ConfigureDialogCurrent::on_checkBoxFreshLogTime_stateChanged(int state){
    if(state)
        ui->checkBoxFreshLogTime->setText(tr("yes"));
    else
        ui->checkBoxFreshLogTime->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshLogSyslog_stateChanged(int state){
    if(state)
        ui->checkBoxFreshLogSyslog->setText(tr("yes"));
    else
        ui->checkBoxFreshLogSyslog->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshLogVerbose_stateChanged(int state){
    if(state)
        ui->checkBoxFreshLogVerbose->setText(tr("yes"));
    else
        ui->checkBoxFreshLogVerbose->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshLogRotate_stateChanged(int state){
    if(state)
        ui->checkBoxFreshLogRotate->setText(tr("yes"));
    else
        ui->checkBoxFreshLogRotate->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshForeground_stateChanged(int state){
    if(state)
        ui->checkBoxFreshForeground->setText(tr("yes"));
    else
        ui->checkBoxFreshForeground->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshDebug_stateChanged(int state){
    if(state)
        ui->checkBoxFreshDebug->setText(tr("yes"));
    else
        ui->checkBoxFreshDebug->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshScriptedUpdates_stateChanged(int state){
    if(state)
        ui->checkBoxFreshScriptedUpdates->setText(tr("yes"));
    else
        ui->checkBoxFreshScriptedUpdates->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshTestDatabases_stateChanged(int state){
    if(state)
        ui->checkBoxFreshTestDatabases->setText(tr("yes"));
    else
        ui->checkBoxFreshTestDatabases->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshCompressLocalDatabase_stateChanged(int state){
    if(state)
        ui->checkBoxFreshCompressLocalDatabase->setText(tr("yes"));
    else
        ui->checkBoxFreshCompressLocalDatabase->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshSafeBrowsing_stateChanged(int state){
    if(state)
        ui->checkBoxFreshSafeBrowsing->setText(tr("yes"));
    else
        ui->checkBoxFreshSafeBrowsing->setText(tr("no"));
}

void ConfigureDialogCurrent::on_checkBoxFreshBytecode_stateChanged(int state){
    if(state)
        ui->checkBoxFreshBytecode->setText(tr("yes"));
    else
        ui->checkBoxFreshBytecode->setText(tr("no"));
}

//Enables Clamd.conf
void ConfigureDialogCurrent::on_checkBoxEnableLocalSocket_stateChanged(int state){
    ui->labelLocalSocket->setEnabled(state);
    ui->lineEditLocalSocket->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLocalSocketGroup_stateChanged(int state){
    ui->labelLocalSocketGroup->setEnabled(state);
    ui->lineEditLocalSocketGroup->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLocalSocketMode_stateChanged(int state){
    ui->labelLocalSocketMode->setEnabled(state);
    ui->lineEditLocalSocketMode->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFixStaleSocket_stateChanged(int state){
    ui->labelFixStaleSocket->setEnabled(state);
    ui->checkBoxFixStaleSocket->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableTCPSocket_stateChanged(int state){
    ui->labelTCPSocket->setEnabled(state);
    ui->spinBoxTCPSocket->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableTCPAddr_stateChanged(int state){
    ui->labelTCPAddr->setEnabled(state);
    ui->stringListTCPAddr->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxConnectionQueueLength_stateChanged(int state){
    ui->labelMaxConnectionQueueLength->setEnabled(state);
    ui->spinBoxMaxConnectionQueueLength->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStreamMaxLength_stateChanged(int state){
    ui->labelStreamMaxLength->setEnabled(state);
    ui->spinBoxStreamMaxLength->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStreamMinPort_stateChanged(int state){
    ui->labelStreamMinPort->setEnabled(state);
    ui->spinBoxStreamMinPort->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStreamMaxPort_stateChanged(int state){
    ui->labelStreamMaxPort->setEnabled(state);
    ui->spinBoxStreamMaxPort->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxThreads_stateChanged(int state){
    ui->labelMaxThreads->setEnabled(state);
    ui->spinBoxMaxThreads->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableReadTimeout_stateChanged(int state){
    ui->labelReadTimeout->setEnabled(state);
    ui->spinBoxReadTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableCommandReadTimeout_stateChanged(int state){
    ui->labelCommandReadTimeout->setEnabled(state);
    ui->spinBoxCommandReadTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableSendBufTimeout_stateChanged(int state){
    ui->labelSendBufTimeout->setEnabled(state);
    ui->spinBoxSendBufTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxQueue_stateChanged(int state){
    ui->labelMaxQueue->setEnabled(state);
    ui->spinBoxMaxQueue->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableIdleTimeout_stateChanged(int state){
    ui->labelIdleTimeout->setEnabled(state);
    ui->spinBoxIdleTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableExcludePath_stateChanged(int state){
    ui->labelExcludePath->setEnabled(state);
    ui->stringListExcludePath->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogFile_stateChanged(int state){
    ui->labelLogFile->setEnabled(state);
    ui->lineEditLogFile->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogFileUnlock_stateChanged(int state){
    ui->labelLogFileUnlock->setEnabled(state);
    ui->checkBoxLogFileUnlock->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogFileMaxSize_stateChanged(int state){
    ui->labelLogFileMaxSize->setEnabled(state);
    ui->spinBoxLogFileMaxSize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogTime_stateChanged(int state){
    ui->labelLogTime->setEnabled(state);
    ui->checkBoxLogTime->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogClean_stateChanged(int state){
    ui->labelLogClean->setEnabled(state);
    ui->checkBoxLogClean->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogSyslog_stateChanged(int state){
    ui->labelLogSyslog->setEnabled(state);
    ui->checkBoxLogSyslog->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogFacility_stateChanged(int state){
    ui->labelLogFacility->setEnabled(state);
    ui->lineEditLogFacility->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogVerbose_stateChanged(int state){
    ui->labelLogVerbose->setEnabled(state);
    ui->checkBoxLogVerbose->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLogRotate_stateChanged(int state){
    ui->labelLogRotate->setEnabled(state);
    ui->checkBoxLogRotate->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableExtendedDetectionInfo_stateChanged(int state){
    ui->labelExtendedDetectionInfo->setEnabled(state);
    ui->checkBoxExtendedDetectionInfo->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePidFile_stateChanged(int state){
    ui->labelPidFile->setEnabled(state);
    ui->lineEditPidFile->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableTemporaryDirectory_stateChanged(int state){
    ui->labelTemporaryDirectory->setEnabled(state);
    ui->lineEditTemporaryDirectory->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableDatabaseDirectory_stateChanged(int state){
    ui->labelDatabaseDirectory->setEnabled(state);
    ui->lineEditDatabaseDirectory->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOfficialDatabaseOnly_stateChanged(int state){
    ui->labelOfficialDatabaseOnly->setEnabled(state);
    ui->checkBoxOfficialDatabaseOnly->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxDirectoryRecursion_stateChanged(int state){
    ui->labelMaxDirectoryRecursion->setEnabled(state);
    ui->spinBoxMaxDirectoryRecursion->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFollowDirectorySymlinks_stateChanged(int state){
    ui->labelFollowDirectorySymlinks->setEnabled(state);
    ui->checkBoxFollowDirectorySymlinks->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFollowFileSymlinks_stateChanged(int state){
    ui->labelFollowFileSymlinks->setEnabled(state);
    ui->checkBoxFollowFileSymlinks->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableCrossFilesystems_stateChanged(int state){
    ui->labelCrossFilesystems->setEnabled(state);
    ui->checkBoxCrossFilesystems->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableSelfCheck_stateChanged(int state){
    ui->labelSelfCheck->setEnabled(state);
    ui->spinBoxSelfCheck->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableDisableCache_stateChanged(int state){
    ui->labelDisableCache->setEnabled(state);
    ui->checkBoxDisableCache->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableVirusEvent_stateChanged(int state){
    ui->labelVirusEvent->setEnabled(state);
    ui->lineEditVirusEvent->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableExitOnOOM_stateChanged(int state){
    ui->labelExitOnOOM->setEnabled(state);
    ui->checkBoxExitOnOOM->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAllowAllMatchScan_stateChanged(int state){
    ui->labelAllowAllMatchScan->setEnabled(state);
    ui->checkBoxAllowAllMatchScan->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableForeground_stateChanged(int state){
    ui->labelForeground->setEnabled(state);
    ui->checkBoxForeground->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableDebug_stateChanged(int state){
    ui->labelDebug->setEnabled(state);
    ui->checkBoxDebug->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableLeaveTemporaryFiles_stateChanged(int state){
    ui->labelLeaveTemporaryFiles->setEnabled(state);
    ui->checkBoxLeaveTemporaryFiles->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableUser_stateChanged(int state){
    ui->labelUser->setEnabled(state);
    ui->lineEditUser->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableBytecode_stateChanged(int state){
    ui->labelBytecode->setEnabled(state);
    ui->checkBoxBytecode->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableBytecodeSecurity_stateChanged(int state){
    ui->labelBytecodeSecurity->setEnabled(state);
    ui->comboBoxBytecodeSecurity->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableBytecodeTimeout_stateChanged(int state){
    ui->labelBytecodeTimeout->setEnabled(state);
    ui->spinBoxBytecodeTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableBytecodeUnsigned_stateChanged(int state){
    ui->labelBytecodeUnsigned->setEnabled(state);
    ui->checkBoxBytecodeUnsigned->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableBytecodeMode_stateChanged(int state){
    ui->labelBytecodeMode->setEnabled(state);
    ui->comboBoxBytecodeMode->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableDetectPUA_stateChanged(int state){
    ui->labelDetectPUA->setEnabled(state);
    ui->checkBoxDetectPUA->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableExcludePUA_stateChanged(int state){
    ui->labelExcludePUA->setEnabled(state);
    ui->stringListExcludePUA->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableIncludePUA_stateChanged(int state){
    ui->labelIncludePUA->setEnabled(state);
    ui->stringListIncludePUA->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanPE_stateChanged(int state){
    ui->labelScanPE->setEnabled(state);
    ui->checkBoxScanPE->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanELF_stateChanged(int state){
    ui->labelScanELF->setEnabled(state);
    ui->checkBoxScanELF->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanMail_stateChanged(int state){
    ui->labelScanMail->setEnabled(state);
    ui->checkBoxScanMail->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanPartialMessages_stateChanged(int state){
    ui->labelScanPartialMessages->setEnabled(state);
    ui->checkBoxScanPartialMessages->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePhishingSignatures_stateChanged(int state){
    ui->labelPhishingSignatures->setEnabled(state);
    ui->checkBoxPhishingSignatures->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePhishingScanURLs_stateChanged(int state){
    ui->labelPhishingScanURLs->setEnabled(state);
    ui->checkBoxPhishingScanURLs->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableHeuristicAlerts_stateChanged(int state){
    ui->labelHeuristicAlerts->setEnabled(state);
    ui->checkBoxHeuristicAlerts->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableHeuristicScanPrecedence_stateChanged(int state){
    ui->labelHeuristicScanPrecedence->setEnabled(state);
    ui->checkBoxHeuristicScanPrecedence->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStructuredDataDetection_stateChanged(int state){
    ui->labelStructuredDataDetection->setEnabled(state);
    ui->checkBoxStructuredDataDetection->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStructuredMinCreditCardCount_stateChanged(int state){
    ui->labelStructuredMinCreditCardCount->setEnabled(state);
    ui->spinBoxStructuredMinCreditCardCount->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStructuredMinSSNCount_stateChanged(int state){
    ui->labelStructuredMinSSNCount->setEnabled(state);
    ui->spinBoxStructuredMinSSNCount->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStructuredSSNFormatNormal_stateChanged(int state){
    ui->labelStructuredSSNFormatNormal->setEnabled(state);
    ui->checkBoxStructuredSSNFormatNormal->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableStructuredSSNFormatStripped_stateChanged(int state){
    ui->labelStructuredSSNFormatStripped->setEnabled(state);
    ui->checkBoxStructuredSSNFormatStripped->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanHTML_stateChanged(int state){
    ui->labelScanHTML->setEnabled(state);
    ui->checkBoxScanHTML->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanOLE2_stateChanged(int state){
    ui->labelScanOLE2->setEnabled(state);
    ui->checkBoxScanOLE2->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanPDF_stateChanged(int state){
    ui->labelScanPDF->setEnabled(state);
    ui->checkBoxScanPDF->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanSWF_stateChanged(int state){
    ui->labelScanSWF->setEnabled(state);
    ui->checkBoxScanSWF->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanXMLDOCS_stateChanged(int state){
    ui->labelScanXMLDOCS->setEnabled(state);
    ui->checkBoxScanXMLDOCS->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanHWP3_stateChanged(int state){
    ui->labelScanHWP3->setEnabled(state);
    ui->checkBoxScanHWP3->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanArchive_stateChanged(int state){
    ui->labelScanArchive->setEnabled(state);
    ui->checkBoxScanArchive->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertBrokenExecutables_stateChanged(int state){
    ui->labelAlertBrokenExecutables->setEnabled(state);
    ui->checkBoxAlertBrokenExecutables->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertEncrypted_stateChanged(int state){
    ui->labelAlertEncrypted->setEnabled(state);
    ui->checkBoxAlertEncrypted->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertEncryptedArchive_stateChanged(int state){
    ui->labelAlertEncryptedArchive->setEnabled(state);
    ui->checkBoxAlertEncryptedArchive->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertEncryptedDoc_stateChanged(int state){
    ui->labelAlertEncryptedDoc->setEnabled(state);
    ui->checkBoxAlertEncryptedDoc->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertOLE2Macros_stateChanged(int state){
    ui->labelAlertOLE2Macros->setEnabled(state);
    ui->checkBoxAlertOLE2Macros->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertExceedsMax_stateChanged(int state){
    ui->labelAlertExceedsMax->setEnabled(state);
    ui->checkBoxAlertExceedsMax->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertPhishingSSLMismatch_stateChanged(int state){
    ui->labelAlertPhishingSSLMismatch->setEnabled(state);
    ui->checkBoxAlertPhishingSSLMismatch->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertPhishingCloak_stateChanged(int state){
    ui->labelAlertPhishingCloak->setEnabled(state);
    ui->checkBoxAlertPhishingCloak->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableAlertPartitionIntersection_stateChanged(int state){
    ui->labelAlertPartitionIntersection->setEnabled(state);
    ui->checkBoxAlertPartitionIntersection->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableForceToDisk_stateChanged(int state){
    ui->labelForceToDisk->setEnabled(state);
    ui->checkBoxForceToDisk->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxScanTime_stateChanged(int state){
    ui->labelMaxScanTime->setEnabled(state);
    ui->spinBoxMaxScanTime->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxScanSize_stateChanged(int state){
    ui->labelMaxScanSize->setEnabled(state);
    ui->spinBoxMaxScanSize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxFileSize_stateChanged(int state){
    ui->labelMaxFileSize->setEnabled(state);
    ui->spinBoxMaxFileSize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxRecursion_stateChanged(int state){
    ui->labelMaxRecursion->setEnabled(state);
    ui->spinBoxMaxRecursion->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxFiles_stateChanged(int state){
    ui->labelMaxFiles->setEnabled(state);
    ui->spinBoxMaxFiles->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxEmbeddedPE_stateChanged(int state){
    ui->labelMaxEmbeddedPE->setEnabled(state);
    ui->spinBoxMaxEmbeddedPE->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxHTMLNormalize_stateChanged(int state){
    ui->labelMaxHTMLNormalize->setEnabled(state);
    ui->spinBoxMaxHTMLNormalize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxHTMLNoTags_stateChanged(int state){
    ui->labelMaxHTMLNoTags->setEnabled(state);
    ui->spinBoxMaxHTMLNoTags->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxScriptNormalize_stateChanged(int state){
    ui->labelMaxScriptNormalize->setEnabled(state);
    ui->spinBoxMaxScriptNormalize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxZipTypeRcg_stateChanged(int state){
    ui->labelMaxZipTypeRcg->setEnabled(state);
    ui->spinBoxMaxZipTypeRcg->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxPartitions_stateChanged(int state){
    ui->labelMaxPartitions->setEnabled(state);
    ui->spinBoxMaxPartitions->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxIconsPE_stateChanged(int state){
    ui->labelMaxIconsPE->setEnabled(state);
    ui->spinBoxMaxIconsPE->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableMaxRecHWP3_stateChanged(int state){
    ui->labelMaxRecHWP3->setEnabled(state);
    ui->spinBoxMaxRecHWP3->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePCREMatchLimit_stateChanged(int state){
    ui->labelPCREMatchLimit->setEnabled(state);
    ui->spinBoxPCREMatchLimit->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePCRERecMatchLimit_stateChanged(int state){
    ui->labelPCRERecMatchLimit->setEnabled(state);
    ui->spinBoxPCRERecMatchLimit->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePCREMaxFileSize_stateChanged(int state){
    ui->labelPCREMaxFileSize->setEnabled(state);
    ui->spinBoxPCREMaxFileSize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessMountPath_stateChanged(int state){
    ui->labelOnAccessMountPath->setEnabled(state);
    ui->stringListOnAccessMountPath->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessIncludePath_stateChanged(int state){
    ui->labelOnAccessIncludePath->setEnabled(state);
    ui->stringListOnAccessIncludePath->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessExcludePath_stateChanged(int state){
    ui->labelOnAccessExcludePath->setEnabled(state);
    ui->stringListOnAccessExcludePath->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessExcludeRootUID_stateChanged(int state){
    ui->labelOnAccessExcludeRootUID->setEnabled(state);
    ui->checkBoxOnAccessExcludeRootUID->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessExcludeUID_stateChanged(int state){
    ui->labelOnAccessExcludeUID->setEnabled(state);
    ui->listSpinBoxOnAccessExcludeUID->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessExcludeUname_stateChanged(int state){
    ui->labelOnAccessExcludeUname->setEnabled(state);
    ui->stringListOnAccessExcludeUname->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessMaxFileSize_stateChanged(int state){
    ui->labelOnAccessMaxFileSize->setEnabled(state);
    ui->spinBoxOnAccessMaxFileSize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessDisableDDD_stateChanged(int state){
    ui->labelOnAccessDisableDDD->setEnabled(state);
    ui->checkBoxOnAccessDisableDDD->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessPrevention_stateChanged(int state){
    ui->labelOnAccessPrevention->setEnabled(state);
    ui->checkBoxOnAccessPrevention->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessExtraScanning_stateChanged(int state){
    ui->labelOnAccessExtraScanning->setEnabled(state);
    ui->checkBoxOnAccessExtraScanning->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessCurlTimeout_stateChanged(int state){
    ui->labelOnAccessCurlTimeout->setEnabled(state);
    ui->spinBoxOnAccessCurlTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessMaxThreads_stateChanged(int state){
    ui->labelOnAccessMaxThreads->setEnabled(state);
    ui->spinBoxOnAccessMaxThreads->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessRetryAttempts_stateChanged(int state){
    ui->labelOnAccessRetryAttempts->setEnabled(state);
    ui->spinBoxOnAccessRetryAttempts->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableOnAccessDenyOnError_stateChanged(int state){
    ui->labelOnAccessDenyOnError->setEnabled(state);
    ui->checkBoxOnAccessDenyOnError->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableDisableCertCheck_stateChanged(int state){
    ui->labelDisableCertCheck->setEnabled(state);
    ui->checkBoxDisableCertCheck->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnablePreludeEnable_stateChanged(int state){
    ui->labelPreludeEnable->setEnabled(state);
    ui->checkBoxPreludeEnable->setEnabled(state);
    //XXX TODO
    //ui->checkBoxPreludeEnable->setChecked(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableScanOnAccess_stateChanged(int state){
    ui->labelScanOnAccess->setEnabled(state);
    ui->checkBoxScanOnAccess->setEnabled(state);
}

//Enables Freshclam.conf
void ConfigureDialogCurrent::on_checkBoxEnableFreshLogFileMaxSize_stateChanged(int state){
    ui->labelFreshLogFileMaxSize->setEnabled(state);
    ui->spinBoxFreshLogFileMaxSize->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshLogTime_stateChanged(int state){
    ui->labelFreshLogTime->setEnabled(state);
    ui->checkBoxFreshLogTime->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshLogSyslog_stateChanged(int state){
    ui->labelFreshLogSyslog->setEnabled(state);
    ui->checkBoxFreshLogSyslog->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshLogFacility_stateChanged(int state){
    ui->labelFreshLogFacility->setEnabled(state);
    ui->lineEditFreshLogFacility->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshLogVerbose_stateChanged(int state){
    ui->labelFreshLogVerbose->setEnabled(state);
    ui->checkBoxFreshLogVerbose->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshLogRotate_stateChanged(int state){
    ui->labelFreshLogRotate->setEnabled(state);
    ui->checkBoxFreshLogRotate->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshPidFile_stateChanged(int state){
    ui->labelFreshPidFile->setEnabled(state);
    ui->lineEditFreshPidFile->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshDatabaseDirectory_stateChanged(int state){
    ui->labelFreshDatabaseDirectory->setEnabled(state);
    ui->lineEditFreshDatabaseDirectory->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshForeground_stateChanged(int state){
    ui->labelFreshForeground->setEnabled(state);
    ui->checkBoxFreshForeground->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshDebug_stateChanged(int state){
    ui->labelFreshDebug->setEnabled(state);
    ui->checkBoxFreshDebug->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshUpdateLogFile_stateChanged(int state){
    ui->labelFreshUpdateLogFile->setEnabled(state);
    ui->lineEditFreshUpdateLogFile->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshDatabaseOwner_stateChanged(int state){
    ui->labelFreshDatabaseOwner->setEnabled(state);
    ui->lineEditFreshDatabaseOwner->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshChecks_stateChanged(int state){
    ui->labelFreshChecks->setEnabled(state);
    ui->spinBoxFreshChecks->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshDNSDatabaseInfo_stateChanged(int state){
    ui->labelFreshDNSDatabaseInfo->setEnabled(state);
    ui->lineEditFreshDNSDatabaseInfo->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshDatabaseMirror_stateChanged(int state){
    ui->labelFreshDatabaseMirror->setEnabled(state);
    ui->stringListFreshDatabaseMirror->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshPrivateMirror_stateChanged(int state){
    ui->labelFreshPrivateMirror->setEnabled(state);
    ui->stringListFreshPrivateMirror->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshMaxAttempts_stateChanged(int state){
    ui->labelFreshMaxAttempts->setEnabled(state);
    ui->spinBoxFreshMaxAttempts->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshScriptedUpdates_stateChanged(int state){
    ui->labelFreshScriptedUpdates->setEnabled(state);
    ui->checkBoxFreshScriptedUpdates->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshTestDatabases_stateChanged(int state){
    ui->labelFreshTestDatabases->setEnabled(state);
    ui->checkBoxFreshTestDatabases->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshCompressLocalDatabase_stateChanged(int state){
    ui->labelFreshCompressLocalDatabase->setEnabled(state);
    ui->checkBoxFreshCompressLocalDatabase->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshExtraDatabase_stateChanged(int state){
    ui->labelFreshExtraDatabase->setEnabled(state);
    ui->stringListFreshExtraDatabase->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshExcludeDatabase_stateChanged(int state){
    ui->labelFreshExcludeDatabase->setEnabled(state);
    ui->stringListFreshExcludeDatabase->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshDatabaseCustomURL_stateChanged(int state){
    ui->labelFreshDatabaseCustomURL->setEnabled(state);
    ui->stringListFreshDatabaseCustomURL->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshHTTPProxyServer_stateChanged(int state){
    ui->labelFreshHTTPProxyServer->setEnabled(state);
    ui->lineEditFreshHTTPProxyServer->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshHTTPProxyPort_stateChanged(int state){
    ui->labelFreshHTTPProxyPort->setEnabled(state);
    ui->spinBoxFreshHTTPProxyPort->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshHTTPProxyUsername_stateChanged(int state){
    ui->labelFreshHTTPProxyUsername->setEnabled(state);
    ui->lineEditFreshHTTPProxyUsername->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshHTTPProxyPassword_stateChanged(int state){
    ui->labelFreshHTTPProxyPassword->setEnabled(state);
    ui->lineEditFreshHTTPProxyPassword->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshHTTPUserAgent_stateChanged(int state){
    ui->labelFreshHTTPUserAgent->setEnabled(state);
    ui->lineEditFreshHTTPUserAgent->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshNotifyClamd_stateChanged(int state){
    ui->labelFreshNotifyClamd->setEnabled(state);
    ui->lineEditFreshNotifyClamd->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshOnUpdateExecute_stateChanged(int state){
    ui->labelFreshOnUpdateExecute->setEnabled(state);
    ui->lineEditFreshOnUpdateExecute->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshOnErrorExecute_stateChanged(int state){
    ui->labelFreshOnErrorExecute->setEnabled(state);
    ui->lineEditFreshOnErrorExecute->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshOnOutdatedExecute_stateChanged(int state){
    ui->labelFreshOnOutdatedExecute->setEnabled(state);
    ui->lineEditFreshOnOutdatedExecute->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshLocalIPAddress_stateChanged(int state){
    ui->labelFreshLocalIPAddress->setEnabled(state);
    ui->lineEditFreshLocalIPAddress->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshConnectTimeout_stateChanged(int state){
    ui->labelFreshConnectTimeout->setEnabled(state);
    ui->spinBoxFreshConnectTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshReceiveTimeout_stateChanged(int state){
    ui->labelFreshReceiveTimeout->setEnabled(state);
    ui->spinBoxFreshReceiveTimeout->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshSafeBrowsing_stateChanged(int state){
    ui->labelFreshSafeBrowsing->setEnabled(state);
    ui->checkBoxFreshSafeBrowsing->setEnabled(state);
}

void ConfigureDialogCurrent::on_checkBoxEnableFreshBytecode_stateChanged(int state){
    ui->labelFreshBytecode->setEnabled(state);
    ui->checkBoxFreshBytecode->setEnabled(state);
}

void ConfigureDialogCurrent::closeEvent(QCloseEvent *event){
    this->hide();
    event->ignore();
}


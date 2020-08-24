#include "MainWindow.h"
#include "ui_MainWindow.h"

QT_CHARTS_USE_NAMESPACE

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

#if QT_VERSION < 0x050a00
    qsrand(time(NULL));
#endif
    QByteArray clamdscan_ver;
    quint32 clamdscan_v = clamdscanVersion(&clamdscan_ver);
    if(CLAMONE_VERSION_L != clamdscan_v){
        QMessageBox::critical(this, windowTitle(),
                              tr("Either ClamAV is not installed or ")+
                              tr("the installed version of ClamAV(")+QString(clamdscan_ver)+
                              tr(") does not match the version of ClamOne(")+QString(CLAMONE_VERSION)+
                              tr("). Please update both for proper operation"), QMessageBox::Ok);
        exitProgram();
    }

    scanAction = new QAction(tr("&Scan..."), this);
    connect(scanAction, &QAction::triggered, this, &MainWindow::scanShow);
    statusAction = new QAction(tr("&Status..."), this);
    connect(statusAction, &QAction::triggered, this, &MainWindow::statusShow);
    updateAction = new QAction(tr("&Update..."), this);
    connect(updateAction, &QAction::triggered, this, &MainWindow::updateShow);
    historyAction = new QAction(tr("E&vent Logs..."), this);
    connect(historyAction, &QAction::triggered, this, &MainWindow::historyShow);
    aboutAction = new QAction(tr("&About..."), this);
    connect(aboutAction, &QAction::triggered, this, &MainWindow::aboutLaunch);
    quitAction = new QAction(tr("&Exit"), this);
    connect(quitAction, &QAction::triggered, this, &MainWindow::actionExit);
    trayIconMenu = new QMenu();
    trayIconMenu->addAction(scanAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(statusAction);
    trayIconMenu->addAction(updateAction);
    trayIconMenu->addAction(historyAction);
    trayIconMenu->addAction(aboutAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayIconMenu);

    statusSetGrey();
    trayIcon->setToolTip(windowTitle());

    setupDb();
    addExistingEvents();
    markClamOneStarted();
    loadScheduleFromDb();

    ui->tableWidgetEventGeneral->setColumnWidth(0, 160);

    intEventGeneralPageNumber = 0;
    initializeEventsGeneralTableWidget(0);
    intEventFoundPageNumber = 0;
    initializeEventsFoundTableWidget(0);
    intEventQuarantinedPageNumber = 0;
    initializeEventsQuarantinedTableWidget(0);
    intMessagesPageNumber = 0;
    initializeMessagesTableWidget(0);

    //Meh, you really probably don't want to run this as root...
    if(!setUID()){
        exitProgram();
        return;
    }
    about = new AboutDialog(this);
    config = new ConfigureDialogCurrent(dbFileLocation, this);
    scanDialog = new ScanDialog();
    listerQuarantine = new ListerQuarantine();
    setEnabledQuarantine(getValDB("enablequarantine")=="yes");

    localSocket = new QLocalSocket(this);
    localSocketFilename = getClamdLocalSocketname();
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::timerSlot);
    timer->start(1000);
    timerSchedule = new QTimer(this);
    connect(timerSchedule, &QTimer::timeout, this, &MainWindow::ckScheduledScans);
    onNextCycle = false;
    quarantineDirectoryWatcher = new QFileSystemWatcher();
    refreshQuarantineDirectory();
    updateQuarantineDirectoryUi("");

    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::iconActivated);
    connect(ui->listWidget, &QListWidget::currentRowChanged, ui->stackedWidget, &QStackedWidget::setCurrentIndex);
    connect(ui->stackedWidget, &QStackedWidget::currentChanged, this, &MainWindow::stackedWidgetChanged);
    connect(ui->comboBoxGraphsSubTitleSelector, QOverload<int>::of(&QComboBox::activated), ui->stackedWidgetGraphs, &QStackedWidget::setCurrentIndex);
    connect(ui->comboBoxLog, QOverload<int>::of(&QComboBox::activated), ui->stackedWidgetEvents, &QStackedWidget::setCurrentIndex);
    connect(config, &ConfigureDialogCurrent::setValDB, this, &MainWindow::setValDB);
    connect(config, &ConfigureDialogCurrent::refreshEventGeneral, this, &MainWindow::initializeEventsGeneralTableWidget);
    connect(config, &ConfigureDialogCurrent::refreshEventFound, this, &MainWindow::initializeEventsFoundTableWidget);
    connect(config, &ConfigureDialogCurrent::refreshEventQuarantined, this, &MainWindow::initializeEventsQuarantinedTableWidget);
    connect(config, &ConfigureDialogCurrent::refreshMessages, this, &MainWindow::initializeMessagesTableWidget);
    connect(config, &ConfigureDialogCurrent::refreshQuarantineDirectory, this, &MainWindow::refreshQuarantineDirectory);
    connect(config, &ConfigureDialogCurrent::setEnabledQuarantine, this, &MainWindow::setEnabledQuarantine);
    connect(this, &MainWindow::addExclusionClamdconf, config, &ConfigureDialogCurrent::addExclusionClamdconf);
    connect(scanDialog, &ScanDialog::parseClamdscanLine, this, &MainWindow::parseClamdscanLine);
    connect(scanDialog, &ScanDialog::initScanProcess, this, &MainWindow::initScanProcess);
    connect(scanDialog, &ScanDialog::setScanActive, this, &MainWindow::setScanActive);
    connect(this, &MainWindow::detectedThreatFound, this, &MainWindow::detectedThreatListener);
    connect(quarantineDirectoryWatcher, &QFileSystemWatcher::directoryChanged, this, &MainWindow::updateQuarantineDirectoryUi);
    connect(listerQuarantine, &ListerQuarantine::yesClicked, this, &MainWindow::ListerQuarantineYesClicked);
    connect(listerQuarantine, &ListerQuarantine::noClicked, this, &MainWindow::ListerQuarantineNoClicked);
    connect(this, &MainWindow::initializeFreelanceScan, scanDialog, &ScanDialog::initializeFreelanceScan);

    cDns.last_lookup_timestamp = 0;

    if(!getClamdLogFileName().isEmpty())
        lastTimestampClamdLogFile = (QFileInfo(getClamdLogFileName()).lastModified().toMSecsSinceEpoch()/1000);
    else
        lastTimestampClamdLogFile = 0;

    p = new QProcess(this);
    p->setProcessChannelMode(QProcess::SeparateChannels);
    connect(p, &QProcess::readyRead, this, &MainWindow::processReadyRead);
    connect(this, &MainWindow::sigProcessReadyRead, scanDialog, &ScanDialog::processReadyRead);
    connect(p, static_cast<void(QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished), scanDialog, &ScanDialog::processFinished);

    isScanActive = false;
    refreshFoundTableOnUpdate = false;

    //Why won't this work with standard dl loading the library, idk
    //There are version problems making it less portable, but it works okay like this.
    if(!(handle = dlopen("libprocps.so", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.6", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.7", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.8", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.9", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.10", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.11", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.12", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.13", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.14", RTLD_LAZY)) &&
       !(handle = dlopen("libprocps.so.15", RTLD_LAZY)) ){
        errorMsg("Error: dlopen failed", false);
        exitProgram();
        return;
    }

    openproc_p = (PROCTAB* (*)(int, ...))dlsym(handle, "openproc");
    if(dlerror() != NULL){
        exitProgram();
        return;
    }

    readproc_p = (proc_t* (*)(PROCTAB *, proc_t *))dlsym(handle, "readproc");
    if(dlerror() != NULL){
        exitProgram();
        return;
    }

    closeproc_p = (void (*)(PROCTAB*))dlsym(handle, "closeproc");
    if(dlerror() != NULL){
        exitProgram();
        return;
    }

    for(int i = 0; i < qMax(QThread::idealThreadCount(),1); i++)
        threads_list.append(new QThread(this));


    QTimer::singleShot(100, [=]() {
        initializeDateTimeLineGraphWidget(1);
        initializeDateTimeLineGraphWidget(2);
        initializeDateTimeLineGraphWidget(3);
    });

    QLabel *imageLabel = new QLabel;
    QImage image(":/images/expl_16.png");
    imageLabel->setPixmap(QPixmap::fromImage(image));

    QLabel *imageLabel2 = new QLabel;
    QImage image2(":/images/expl_16.png");
    imageLabel2->setPixmap(QPixmap::fromImage(image2));
}


MainWindow::~MainWindow(){
    delete ui;
    dlclose(handle);
}

void MainWindow::allHide(){
    setVisible(false);
    about->hide();
    config->hide();
    scanDialog->hide();
}

void MainWindow::scanShow(){
    allShow();
    ui->stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Scan);
    ui->listWidget->setCurrentRow(ClamOneMainStackOrder::Scan);
}

void MainWindow::statusShow(){
    allShow();
    ui->stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Status);
    ui->listWidget->setCurrentRow(ClamOneMainStackOrder::Status);
}

void MainWindow::historyShow(){
    allShow();
    ui->stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Log);
    ui->listWidget->setCurrentRow(ClamOneMainStackOrder::Log);
}

void MainWindow::updateShow(){
    allShow();
    ui->stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Update);
    ui->listWidget->setCurrentRow(ClamOneMainStackOrder::Update);
}

void MainWindow::aboutLaunch(){
    about->show();
}

void MainWindow::configLaunch(){
    quint32 ret = checkCurrentClamavVersionInstalled();
    if(ret > 0xFFFFFFF7){
        errorMsg("Bad: ClamAV Version Installed: " + QString::number(ret, 16));
        exitProgram();
    }
    if(ret < QT_VERSION_CHECK(0, 101, 4)){
        //hide MaxScanTime < 0.101.4
        //hide OnAccessExcludeUname < 0.102.0
        //hide OnAccessCurlTimeout < 0.102.0
        //hide OnAccessMaxThreads < 0.102.0
        //hide OnAccessRetryAttempts < 0.102.0
        //hide OnAccessDenyOnError < 0.102.0
    }else if(ret < QT_VERSION_CHECK(0, 102, 0)){
        //show MaxScanTime >= 0.101.4
        //show ScanOnAccess < 0.102.0
        //hide OnAccessExcludeUname < 0.102.0
        //hide OnAccessCurlTimeout < 0.102.0
        //hide OnAccessMaxThreads < 0.102.0
        //hide OnAccessRetryAttempts < 0.102.0
        //hide OnAccessDenyOnError < 0.102.0
    }else{
        config->show();
        config->updateClamdconfLoc(getValDB("clamdconf"));
        config->updateFreshclamconfLoc(getValDB("freshclamconf"));
        config->updateMonitorOnAccess(getValDB("monitoronaccess")=="yes");
        config->updateEntriesPerPage(getValDB("entriesperpage"));
        config->updateEnableQuarantine(getValDB("enablequarantine")=="yes");
        config->updateMaximumQuarantineFileSize(getValDB("maxquarantinesize").toInt());
        config->updateLocationQuarantineFileDirectory(getValDB("quarantinefilesdirectory"));
        //show MaxScanTime >= 0.101.4
        //hide ScanOnAccess >= 0.102.0
        //show OnAccessExcludeUname >= 0.102.0
        //show OnAccessCurlTimeout >= 0.102.0
        //show OnAccessMaxThreads >= 0.102.0
        //show OnAccessRetryAttempts >= 0.102.0
        //show OnAccessDenyOnError >= 0.102.0
    }
}

quint32 MainWindow::checkCurrentClamavVersionInstalled(){
    QProcess whichClamdProc;
    whichClamdProc.start("which", QStringList({"clamd"}));
    whichClamdProc.waitForFinished();
    QByteArray whichClamdRet = whichClamdProc.readAllStandardOutput();
    whichClamdRet = ((whichClamdRet.mid(whichClamdRet.length()-1, 1) == QByteArray("\n",1))?whichClamdRet.mid(0, whichClamdRet.length()-1):whichClamdRet);
    whichClamdProc.close();
    if(whichClamdRet.isEmpty())
        return 0xFFFFFFFF;

    QProcess clamdVersionProc;
    clamdVersionProc.start(whichClamdRet, QStringList({"-V"}));
    clamdVersionProc.waitForFinished();
    QByteArray clamdVersionRet = clamdVersionProc.readAllStandardOutput();
    if(clamdVersionRet.isEmpty())
        return 0xFFFFFFFE;
    QStringList versionNums = QString(clamdVersionRet).split("/");
    if(versionNums.length() != 3)
        return 0xFFFFFFFD;
    versionNums = versionNums[0].split(" ");
    if(versionNums.length() != 2)
        return 0xFFFFFFFC;
    versionNums = versionNums[1].split(".");
    if(versionNums.length() != 3)
        return 0xFFFFFFFB;
    bool ok = true;
    quint8 num1 = versionNums[0].toInt(&ok);
    if(!ok)
        return 0xFFFFFFFA;
    quint8 num2 = versionNums[1].toInt(&ok);
    if(!ok)
        return 0xFFFFFFF9;
    quint8 num3 = versionNums[2].toInt(&ok);
    if(!ok)
        return 0xFFFFFFF8;
    return QT_VERSION_CHECK(num1, num2, num3);
}

bool MainWindow::setupDb(){
    QString homeLocation = QStandardPaths::writableLocation(
        QStandardPaths::ConfigLocation)+QString(PATHSEP "ClamOne" PATHSEP);
    if(homeLocation.isEmpty()){
        exitProgram();
    }
    if(!QDir(homeLocation).exists()){
        QDir().mkdir(homeLocation);
    }
    QFile dbFile(homeLocation+"clamone.db");
    if(!dbFile.open(QIODevice::ReadWrite)){
        exitProgram();
    }
    dbFile.close();
    dbFileLocation = homeLocation+"clamone.db";

    const QString DRIVER("QSQLITE");
    if(!QSqlDatabase::isDriverAvailable(DRIVER))
        return false;
    db = QSqlDatabase::addDatabase(DRIVER);
    db.setDatabaseName(dbFileLocation);
    if(!db.open()){
        qWarning() << "ERROR: " << db.lastError();
        db.setDatabaseName(":memory:");
        if(!db.open()){
            qWarning() << "ERROR: " << db.lastError();
            return false;
        }
    }
    QSqlQuery query;
    query.prepare("CREATE TABLE IF NOT EXISTS basics( `key` TEXT NOT NULL UNIQUE, `val` TEXT NOT NULL, PRIMARY KEY(`key`) )");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS logfiles( `timestamp` INTEGER NOT NULL UNIQUE, PRIMARY KEY(`timestamp`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS freshlogfiles( `timestamp` INTEGER NOT NULL UNIQUE, PRIMARY KEY(`timestamp`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS general( `timestamp` INTEGER NOT NULL, `message` TEXT NOT NULL, PRIMARY KEY(`timestamp`,`message`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS found( `timestamp` INTEGER NOT NULL, `message` TEXT NOT NULL, "
                  "`alreadyread` INTEGER NOT NULL, `existsonfs` INTEGER NOT NULL, `filename` TEXT, PRIMARY KEY(`timestamp`,`message`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS freshlog( `timestamp` INTEGER NOT NULL, `message` TEXT NOT NULL, PRIMARY KEY(`timestamp`,`message`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS messages( `timestamp` INTEGER NOT NULL, `message` TEXT NOT NULL, PRIMARY KEY(`timestamp`,`message`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS quarantine(`quarantine_name` TEXT NOT NULL UNIQUE, `timestamp` INTEGER, `file_size` INTEGER, `file_name` TEXT, `verified` INTEGER NOT NULL);");
    query.exec();
    //verified: (1, UNKNOWN) (2, VERIFIED GOOD) (3, VERIFIED BAD)
    query.prepare("CREATE TABLE IF NOT EXISTS quarantine_log(`timestamp` INTEGER NOT NULL, `message` TEXT NOT NULL, PRIMARY KEY(`timestamp`,`message`) );");
    query.exec();
    query.prepare("CREATE TABLE IF NOT EXISTS counts_table(`timestamp` INTEGER NOT NULL, `state` TEXT NOT NULL, `num` INTEGER NOT NULL, PRIMARY KEY(`timestamp`,`state`) );");
    query.exec();
    //state: (1, SCANNED) (2, INFECTED) (3, QUARANTINED) (4, REMOVED)
    query.prepare("CREATE TABLE IF NOT EXISTS schedule(`enable` INTEGER, `name` TEXT, `minute` TEXT, `hour` TEXT, `daymonth` TEXT, `month` TEXT, `dayweek` TEXT, `stringlist` BLOB );");
    query.exec();

    QString res = getValDB("clamdconf");
    if(res.isEmpty()){
        setValDB("clamdconf",
#ifndef _WIN32
        "/etc/clamav/clamd.conf"
#else
        "C:\\ClamAV\\clamd.conf"
#endif
        );
    }

    res = getValDB("freshclamconf");
    if(res.isEmpty()){
        setValDB("freshclamconf",
#ifndef _WIN32
        "/etc/clamav/freshclam.conf"
#else
        "C:\\ClamAV\\freshclam.conf"
#endif
        );
    }

    res = getValDB("monitoronaccess");
    if(res.isEmpty()){
        setValDB("monitoronaccess", "no");
    }

    res = getValDB("entriesperpage");
    if(res.isEmpty()){
        setValDB("entriesperpage", "40");
    }else{
        bool ok = false;
        int num = res.toInt(&ok, 10);
        if(!ok || num > 1000000 || num < 1)
            setValDB("entriesperpage", "40");
    }

    res = getValDB("enablequarantine");
    if(res.isEmpty()){
        setValDB("enablequarantine", "yes");
    }

    res = getValDB("maxquarantinesize");
    if(res.isEmpty()){
        setValDB("maxquarantinesize", "25000000");
    }else{
        bool ok = false;
        int num = res.toInt(&ok, 10);
        if(!ok || num < 1)
            setValDB("maxquarantinesize", "25000000");
    }

    res = getValDB("quarantinefilesdirectory");
    if(res.isEmpty()){
        setValDB("quarantinefilesdirectory", homeLocation+tr("quarantine" PATHSEP));
    }
    QFileInfo qfd(getValDB("quarantinefilesdirectory"));
    if(!qfd.exists())
        QDir().mkpath(qfd.absoluteFilePath());

    return true;
}

void MainWindow::markClamOneStarted(){
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO messages (timestamp, message) VALUES ( :ts , :msg );");
    query.bindValue(":ts", (quint32)time(NULL));
    query.bindValue(":msg", "+++ Clam One Started");
    query.exec();
}

void MainWindow::markClamOneStopped(){
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO messages (timestamp, message) VALUES ( :ts , :msg );");
    query.bindValue(":ts", (quint32)time(NULL));
    query.bindValue(":msg", "--- Clam One Stopped");
    query.exec();
}

void MainWindow::loadScheduleFromDb(){
    QSqlQuery query;
    query.prepare("SELECT * FROM schedule ;");
    query.exec();
    while(query.next()){
        bool enable = query.value(0).toBool();
        QString name = query.value(1).toString();
        QString minute = query.value(2).toString();
        QString hour = query.value(3).toString();
        QString daymonth = query.value(4).toString();
        QString month = query.value(5).toString();
        QString dayweek = query.value(6).toString();
        QByteArray blob = query.value(7).toByteArray();
        QList<QByteArray> byteList = blob.split('\0');
        QStringList stringList;
        foreach(QByteArray b, byteList){
            if(!b.isEmpty())
                stringList.append(QString(b));
        }
        add_new_schedule(enable,name,minute,hour,daymonth,month,dayweek,stringList);
    }
    schedule_detected_change();
}

void MainWindow::markQuarantineNewFile(QByteArray filename){
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO quarantine_log (timestamp, message) VALUES ( :ts , :msg );");
    query.bindValue(":ts", (quint32)time(NULL));
    query.bindValue(":msg", tr("Quarantined File: ")+QString(filename));
    query.exec();
}

void MainWindow::markQuarantineDeleteQ(QByteArray filename){
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO quarantine_log (timestamp, message) VALUES ( :ts , :msg );");
    query.bindValue(":ts", (quint32)time(NULL));
    query.bindValue(":msg", tr("Permanently Deleted Quarantined File: ")+QString(filename));
    query.exec();
}

void MainWindow::markQuarantineUnQ(QByteArray filename){
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO quarantine_log (timestamp, message) VALUES ( :ts , :msg );");
    query.bindValue(":ts", (quint32)time(NULL));
    query.bindValue(":msg", tr("Restored Quarantined File: ")+QString(filename));
    query.exec();
}

void MainWindow::stackedWidgetChanged(int index){
    Q_UNUSED(index)
    ui->stackedWidget->currentWidget()->setFocus();
}

bool MainWindow::addExistingEvents(){
    //Parse clamd log files
    QRegularExpression re;
    QString logfileVar = getClamdLogFileName();
    if(logfileVar.isEmpty() || !QFileInfo(logfileVar).exists())
        return false;

    QDir dir = QFileInfo(logfileVar).absoluteDir();
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
    QStringList list = dir.entryList();
    re.setPattern("^"+logfileVar);
    for (int i = 0; i < list.size(); ++i) {
        if(re.match(dir.path().toLocal8Bit()+tr("/")+list.at(i).toLocal8Bit()).hasMatch()){
            addExistingEventsParseClamlog(dir.path()+tr("/")+list.at(i), true, false);
        }
    }

    //Parse freshclam log files
    logfileVar = getClamdUpdateLogFileName();
    if(logfileVar.isEmpty() || !QFileInfo(logfileVar).exists())
        return false;

    dir = QFileInfo(logfileVar).dir();
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
    list = dir.entryList();
    re.setPattern("^"+logfileVar);
    for (int i = 0; i < list.size(); ++i) {
        if(re.match(dir.path().toLocal8Bit()+tr("/")+list.at(i).toLocal8Bit()).hasMatch()){
            addExistingEventsParseFreshclam(dir.path()+tr("/")+list.at(i), true);
        }
    }
    return true;
}

bool MainWindow::addExistingEventsParseClamlog(QString filename, bool verify, bool active){
    bool exists = false;
    QSqlDatabase::database().transaction();
    QSqlQuery query;
    if(verify){
        query.prepare("SELECT COUNT(*) FROM logfiles WHERE timestamp = :ts ;");
        query.bindValue(":ts", (QFileInfo(filename).lastModified().toMSecsSinceEpoch()/1000));
        query.exec();
        if(query.next()){
            exists = query.value(0).toBool();
        }else{
            exitProgram();
        }
    }

    if(!exists){
        QFile log(filename);
        if(log.open(QFile::ReadOnly)){
            QByteArray bytes = log.readAll();
            QRegularExpression regex;
            regex.setPattern("\\.gz$");
            if(regex.match(QFileInfo(filename).fileName()).hasMatch()){
                bytes = gUncompress(bytes);
            }
            QBuffer buffer;
            buffer.open(QIODevice::ReadWrite);
            buffer.write(bytes);
            buffer.seek(0);
            while(buffer.canReadLine()){
                QByteArray line = buffer.readLine();
                QString message = "";
                qint64 timestamp = 0;
                bool found = false;
                parseClamavLogLine(line, &timestamp, &message, &found);

                QRegularExpression reFound;
                reFound.setPattern("^.* FOUND$");
                QRegularExpressionMatch reFoundMatch = reFound.match(message);
                if(!found && reFoundMatch.hasMatch())
                    continue;
                insertIntoFoundOrGeneral(timestamp, message, found, active);
            }
        }
        log.close();
        query.prepare("INSERT OR IGNORE INTO logfiles (timestamp) VALUES ( :ts );");
        query.bindValue(":ts", (QFileInfo(filename).lastModified().toMSecsSinceEpoch()/1000));
        query.exec();
    }

    QSqlDatabase::database().commit();
    return true;
}

bool MainWindow::addExistingEventsParseFreshclam(QString filename, bool verify){
    bool exists = false;
    QSqlDatabase::database().transaction();
    QSqlQuery query;
    if(verify){
        query.prepare("SELECT COUNT(*) FROM freshlogfiles WHERE timestamp = :ts ;");
        query.bindValue(":ts", (QFileInfo(filename).lastModified().toMSecsSinceEpoch()/1000));
        query.exec();
        if(query.next()){
            exists = query.value(0).toBool();
        }else{
            exitProgram();
        }
    }
    if(!exists){
        QFile log(filename);
        if(log.open(QFile::ReadOnly)){
            QByteArray bytes = log.readAll();
            QRegularExpression regex;
            regex.setPattern("\\.gz$");
            if(regex.match(QFileInfo(filename).fileName()).hasMatch()){
                bytes = gUncompress(bytes);
            }
            QBuffer buffer;
            buffer.open(QIODevice::ReadWrite);
            buffer.write(bytes);
            buffer.seek(0);
            while(buffer.canReadLine()){
                QByteArray line = buffer.readLine();
                QString message = "";
                qint64 timestamp = 0;
                bool matched = false;
                parseFreshclamLogLine(line, &buffer, &timestamp, &message, &matched);
                if(matched){
                    query.prepare("INSERT OR IGNORE INTO freshlog (timestamp, message) VALUES ( :ts , :msg );");
                    query.bindValue(":ts", timestamp);
                    query.bindValue(":msg", message);
                    query.exec();
                }
            }
        }
        log.close();
        query.prepare("INSERT OR IGNORE INTO freshlogfiles (timestamp) VALUES ( :ts );");
        query.bindValue(":ts", (QFileInfo(filename).lastModified().toMSecsSinceEpoch()/1000));
        query.exec();
    }

    QSqlDatabase::database().commit();
    return true;
}

bool MainWindow::parseClamavLogLine(QByteArray line, qint64 *ts, QString *msg, bool *found){
    QRegularExpression reLine;
    reLine.setPattern("^(.*) -> (.*)$");
    QRegularExpressionMatch reLineMatch = reLine.match(line);
    if(reLineMatch.hasMatch()){
        QString timestamp = reLineMatch.captured(1);
        QString message = reLineMatch.captured(2);

        QRegularExpression reFound;
        reFound.setPattern("^/.* FOUND$");
        QRegularExpressionMatch reFoundMatch = reFound.match(message);

        (*found) = reFoundMatch.hasMatch();
        (*ts) = (QDateTime::fromString(timestamp).toMSecsSinceEpoch()/1000);
        (*msg) = message;
        return true;
    }
    return false;
}

void MainWindow::parseClamdscanLine(QByteArray line){
    QList<QByteArray> split = line.split('\n');
    foreach(QByteArray qba, split){
        QRegularExpression reFound;
        reFound.setPattern("^/.* FOUND$");
        QRegularExpressionMatch reFoundMatch = reFound.match(QString(qba));
        if(reFoundMatch.hasMatch()){
            insertIntoFoundOrGeneral((qint64)time(NULL), QString(qba), true, true);
        }
    }
}

void MainWindow::insertIntoFoundOrGeneral(qint64 timestamp, QString message, bool found, bool active){
    QSqlQuery query;
    QString threatMessage = "";
    bool existsInDatabaseAlready = false;
    query.prepare("SELECT COUNT(*) FROM found WHERE timestamp = :ts AND message = :msg ;");
    query.bindValue(":ts", timestamp);
    query.bindValue(":msg", message);
    query.exec();
    if(query.next()){
        existsInDatabaseAlready = query.value(0).toBool();
    }

    if(found){
        QRegularExpression re;
        QRegularExpressionMatch reMatch;
        re.setPattern("^(.*): [^ ]+ FOUND$");
        reMatch = re.match(message);
        query.prepare("INSERT OR IGNORE INTO found (timestamp, message, alreadyread, existsonfs, filename) VALUES ( :ts , :msg, :read, :existsonfs, :filename );");
        if(active){
            query.bindValue(":read", 0);
        }else{
            query.bindValue(":read", 1);
        }
        if(reMatch.hasMatch()){
            query.bindValue(":filename", reMatch.captured(1));
            QFileInfo fileFound(reMatch.captured(1));
            if(fileFound.exists()){
                query.bindValue(":existsonfs", 1);
            }else{
                query.bindValue(":existsonfs", 0);
            }
        }else{
            query.bindValue(":existsonfs", 0);
        }
        threatMessage = (reMatch.hasMatch())?reMatch.captured(1):"";
    }else{
        query.prepare("INSERT OR IGNORE INTO general (timestamp, message) VALUES ( :ts , :msg );");
    }

    query.bindValue(":ts", timestamp);
    query.bindValue(":msg", message);
    query.exec();
    if(found && active && !existsInDatabaseAlready){
        emit detectedThreatFound(message, threatMessage);

        allShow();

        quint32 ts = (quint32)time(NULL);
        QSqlQuery query;
        query.prepare("INSERT OR IGNORE INTO counts_table(timestamp, state, num) VALUES (:timestamp1, 2, 0);");
        query.bindValue(":timestamp1", ts);
        query.exec();
        query.prepare("UPDATE counts_table SET num = num + 1 WHERE timestamp = :timestamp1 AND state = 2 ;");
        query.bindValue(":timestamp1", ts);
        query.exec();
    }
}

bool MainWindow::parseFreshclamLogLine(QByteArray line, QBuffer *buffer, qint64 *ts, QString *msg, bool *matched){
    QByteArray msgbytes = QByteArray();
    QRegularExpression reLine;
    reLine.setPattern("^(.*) -> (.*)$");
    QRegularExpressionMatch reLineMatch = reLine.match(line);
    if(reLineMatch.hasMatch()){
        QString timestamp = reLineMatch.captured(1);
        QString message = reLineMatch.captured(2);
        quint64 ts_num = (QDateTime::fromString(timestamp).toMSecsSinceEpoch()/1000);
        Q_UNUSED(ts_num)

        QRegularExpression reFreshclamDaemon;
        reFreshclamDaemon.setPattern("^freshclam daemon .*$");
        QRegularExpressionMatch reFreshclamDaemonMatch = reFreshclamDaemon.match(message);

        QRegularExpression reReceivedSignalWakeUp;
        reReceivedSignalWakeUp.setPattern("^Received signal: wake up$");
        QRegularExpressionMatch reReceivedSignalWakeUpMatch = reReceivedSignalWakeUp.match(message);

        QRegularExpression reReceivedSignalReOpen;
        reReceivedSignalReOpen.setPattern("^Received signal: re-opening log file$");
        QRegularExpressionMatch reReceivedSignalReOpenMatch = reReceivedSignalReOpen.match(message);

        QRegularExpression reUpdateProcessStarted;
        reUpdateProcessStarted.setPattern("^ClamAV update process started at .*$");
        QRegularExpressionMatch reUpdateProcessStartedMatch = reUpdateProcessStarted.match(message);

        QRegularExpression reUpdateProcessTerminated;
        reUpdateProcessTerminated.setPattern("^Update process terminated$");
        QRegularExpressionMatch reUpdateProcessTerminatedMatch = reUpdateProcessTerminated.match(message);

        (*matched) = reFreshclamDaemonMatch.hasMatch() ||
                reReceivedSignalWakeUpMatch.hasMatch() ||
                reReceivedSignalReOpenMatch.hasMatch() ||
                reUpdateProcessStartedMatch.hasMatch() ||
                reUpdateProcessTerminatedMatch.hasMatch();
        if(*matched){
            msgbytes = message.toLocal8Bit()+tr("\n").toLocal8Bit();
            while((*buffer).canReadLine()){
                line = (*buffer).readLine();
                reLine.setPattern("^(.*) -> (.*)$");
                reLineMatch = reLine.match(line);
                if(reLineMatch.hasMatch()){
                    timestamp = reLineMatch.captured(1);
                    message = reLineMatch.captured(2);
                    reLine.setPattern("^--------------------------------------$");
                    reLineMatch = reLine.match(message);
                    msgbytes.append(message.toLocal8Bit());
                    if(reLineMatch.hasMatch()){
                        break;
                    }else{
                        msgbytes.append(tr("\n").toLocal8Bit());
                    }
                }
            }
            (*ts) = (QDateTime::fromString(timestamp).toMSecsSinceEpoch()/1000);
            (*msg) = QString(msgbytes);
        }
    }
    return true;
}

qint64 MainWindow::initializeEventsGeneralTableWidget(qint64 page){
    qint64 num = 0;
    qint64 entriesperpage = getEntriesPerPage();
    qint64 width = 1;

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM general;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > 0){
            if(entriesperpage*(page+1) > num)
                ui->labelEventGeneralPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                ui->labelEventGeneralPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            ui->labelEventGeneralPagePosition->setText(tr("0 - 0 (0 entries total)"));
            return 0;
        }
    }

    query.prepare("SELECT * FROM general ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(ui->tableWidgetEventGeneral->rowCount())
        ui->tableWidgetEventGeneral->removeRow(0);
    ui->tableWidgetEventGeneral->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);

    while(query.next()){
        QTableWidgetItem *item = new QTableWidgetItem(query.value(1).toString());
        if(query.value(1).toString().length() > width)
            width = query.value(1).toString().length();

        ui->tableWidgetEventGeneral->insertRow(ui->tableWidgetEventGeneral->rowCount());
        ui->tableWidgetEventGeneral->setItem(ui->tableWidgetEventGeneral->rowCount()-1,0,
             new QTableWidgetItem(
                 QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP")
             ));
        ui->tableWidgetEventGeneral->setItem(ui->tableWidgetEventGeneral->rowCount()-1,1, item);
    }
    ui->tableWidgetEventGeneral->resizeColumnToContents(1);
    ui->tableWidgetEventGeneral->horizontalScrollBar()->setValue(0);
    ui->tableWidgetEventGeneral->verticalScrollBar()->setValue(0);
    return num;
}

qint64 MainWindow::initializeMessagesTableWidget(qint64 page){
    qint64 num = 0;
    qint64 entriesperpage = getEntriesPerPage();
    qint64 width = 100;

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM messages;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > 0){
            if(entriesperpage*(page+1) > num)
                ui->labelMessagesPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                ui->labelMessagesPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            ui->labelMessagesPagePosition->setText(tr("0 - 0 (0 entries total)"));
            while(ui->tableWidgetMessages->rowCount())
                ui->tableWidgetMessages->removeRow(0);
            return 0;
        }
    }

    query.prepare("SELECT * FROM messages ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(ui->tableWidgetMessages->rowCount())
        ui->tableWidgetMessages->removeRow(0);
    ui->tableWidgetMessages->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);
    while(query.next()){
        QTableWidgetItem *item = new QTableWidgetItem(query.value(1).toString());
        if(query.value(1).toString().length() > width)
            width = query.value(1).toString().length();
        ui->tableWidgetMessages->insertRow(ui->tableWidgetMessages->rowCount());
        ui->tableWidgetMessages->setItem(ui->tableWidgetMessages->rowCount()-1,0,new QTableWidgetItem(
            QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP")
        ));
        ui->tableWidgetMessages->setItem(ui->tableWidgetMessages->rowCount()-1,1, item);
    }
    ui->tableWidgetMessages->horizontalScrollBar()->setValue(0);
    ui->tableWidgetMessages->verticalScrollBar()->setValue(0);
    return num;
}

void MainWindow::initializeDateTimeLineGraphWidget(int state){
    int n;
    QList<QPair<qlonglong, int> > dataset0;
    QPair<qlonglong, int> tmpdataset;
    QBarSeries *seriesScan1 = new QBarSeries();
    QBarSet *set0 = new QBarSet("");

    qreal delta_ts;
    quint64 ts_range_1, ts_range_2;
    QChart *chart = new QChart();
    chart->setMinimumHeight(200);
    QColor color;

    if(state == 1){
        delta_ts = DELTA_BASE * pow(2., graphs_scaned_xscale);
        ts_range_2 = QDateTime::currentDateTime().toSecsSinceEpoch()-graphs_scaned_xshift;
        ts_range_1 =  ts_range_2 - delta_ts;
        ui->labelGraphsScanedXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        ui->labelGraphsScanedXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        ui->chartviewScanned->setChart(chart);
        color = QColor::fromRgb(0,0,255);
    }else if(state == 2){
        delta_ts = DELTA_BASE * pow(2., graphs_found_xscale);
        ts_range_2 = QDateTime::currentDateTime().toSecsSinceEpoch()-graphs_found_xshift;
        ts_range_1 =  ts_range_2 - delta_ts;
        ui->labelGraphsFoundXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        ui->labelGraphsFoundXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        ui->chartviewFound->setChart(chart);
        color = QColor::fromRgb(255,0,0);
    }else if(state == 3){
        delta_ts = DELTA_BASE * pow(2., graphs_quarantine_xscale);
        ts_range_2 = QDateTime::currentDateTime().toSecsSinceEpoch()-graphs_quarantine_xshift;
        ts_range_1 =  ts_range_2 - delta_ts;
        ui->labelGraphsQuarantineXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        ui->labelGraphsQuarantineXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        ui->chartviewQuarantine->setChart(chart);
        color = QColor::fromRgb(0,255,0);
    }else{
        return;
    }

    chart->legend()->hide();

    set0->setColor(color);
    QSqlQuery query;
    query.prepare("SELECT timestamp, num FROM counts_table WHERE state = :state AND timestamp >= :tsmin AND timestamp <= :tsmax ORDER BY timestamp ASC;");
    query.bindValue(":state", state);
    query.bindValue(":tsmin", ts_range_1);
    query.bindValue(":tsmax",  ts_range_2);
    query.exec();
    while(query.next()){
        tmpdataset.first = query.value(0).toLongLong();
        tmpdataset.second = query.value(1).toInt();
        dataset0.append(tmpdataset);
    }

    QStringList catagories;
    if(delta_ts > (DELTA_YEAR)){
        n = 18;
        for(int i = 0; i < n; i++){
            catagories.append(QDateTime::fromSecsSinceEpoch(ts_range_1 +i*(delta_ts/(qreal)n)).toString("MMM-yyyy"));
        }
    }else{
        n = 7;
        for(int i = 0; i < n; i++){
            catagories.append(QDateTime::fromSecsSinceEpoch(ts_range_1 +i*(delta_ts/(qreal)n)).toString("MMMdd hh:mmap"));
        }
    }
    for(int i = 0; i < n; i++)
        set0->append(0);

    foreach(tmpdataset, dataset0){
        bool isFound = false;
        for(int i = 0; i < n; i++){
            if(tmpdataset.first > (ts_range_1 +i*(delta_ts/(qreal)n))
                    &&
               tmpdataset.first <= (ts_range_1 +(i+1)*(delta_ts/(qreal)n))){
                set0->replace(i, set0->at(i) + tmpdataset.second);
                isFound = true;
                break;
            }
        }
        if(!isFound){
            return;
        }
    }

    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    QFont fnt = axisX->labelsFont();
    fnt.setPixelSize(8);
    fnt.setStyleHint(QFont::Monospace);
    axisX->setLabelsFont(fnt);
    axisX->append(catagories);
    axisX->setLabelsAngle(90);

    seriesScan1->append(set0);
    chart->addSeries(seriesScan1);

    chart->addAxis(axisX, Qt::AlignBottom);
    seriesScan1->attachAxis(axisX);

    QValueAxis *axisY = new QValueAxis;
    fnt = axisY->labelsFont();
    fnt.setPixelSize(8);
    fnt.setStyleHint(QFont::Monospace);
    axisY->setLabelsFont(fnt);
    axisY->setLabelFormat("%i");
    chart->addAxis(axisY, Qt::AlignLeft);
    seriesScan1->attachAxis(axisY);
    axisY->setMin(0.0);

}

void MainWindow::refreshQuarantineDirectory(){
    if(!quarantineDirectoryWatcher->directories().empty())
        quarantineDirectoryWatcher->removePaths(quarantineDirectoryWatcher->directories());
    if(!quarantineDirectoryWatcher->files().empty())
        quarantineDirectoryWatcher->removePaths(quarantineDirectoryWatcher->files());
    QString path = getValDB("quarantinefilesdirectory");
    if(!QFileInfo(path).exists())
        QDir().mkpath(path);
    if(!QFileInfo(path).exists() || !QFileInfo(path).isDir() || !QFileInfo(path).isWritable())
        return;
    quarantineDirectoryWatcher->addPath(path);
}

void MainWindow::updateQuarantineDirectoryUi(const QString path){
    Q_UNUSED(path)
    QString qpath = getValDB("quarantinefilesdirectory");

    while(ui->tableWidgetQuarantine->rowCount())
        ui->tableWidgetQuarantine->removeRow(0);

    qint64 width = 100;
    QDir dir = QFileInfo(qpath).dir();
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
    ui->tableWidgetQuarantine->setColumnWidth(0, 270);
    ui->tableWidgetQuarantine->setColumnWidth(1, 160);
    ui->tableWidgetQuarantine->setColumnWidth(2, 60);
    ui->tableWidgetQuarantine->horizontalHeaderItem(3)->setTextAlignment(Qt::AlignLeft);
    ui->tableWidgetQuarantine->setSortingEnabled(false);
    foreach(QFileInfo qfi, dir.entryInfoList()){
        if(qfi.absolutePath().length() > width)
            width = qfi.fileName().length();
        quint8 verifiedStatus = getQuarantineFileStatus(qfi.fileName());
        if(verifiedStatus == 3)
            continue;
        QByteArray filename = QByteArray();
        quint32 timestamp = 0;
        quint64 file_size = 0;
        if(verifiedStatus != 2){
            QFile qf(qfi.absoluteFilePath());
            if(!qf.open(QFile::ReadOnly)){
                qDebug() << "locked file not read only";
                updateDbQuarantine(qfi.fileName().toLocal8Bit(), 0, 0, QByteArray(), 1);
                continue;
            }
            if(!QAES().verify(qf.readAll(), &filename, &timestamp, &file_size)){
                qDebug() << "QAES not verified";
                updateDbQuarantine(qfi.fileName().toLocal8Bit(), timestamp, file_size, filename, 3);
                qf.close();
                continue;
            }else{
                updateDbQuarantine(qfi.fileName().toLocal8Bit(), timestamp, file_size, filename, 2);
                qf.close();
            }
        }else{
            getQuarantineInfo(qfi.fileName(), &timestamp, &file_size, &filename);
        }

        ui->tableWidgetQuarantine->insertRow(ui->tableWidgetQuarantine->rowCount());

        QTableWidgetItem *item0 = new QTableWidgetItem(qfi.fileName());
        QTableWidgetItem *item1 = new TimestampTableWidgetItem(timestamp);
        QTableWidgetItem *item2 = new QTableWidgetItem((file_size>(1<<30))?
            QString::number(file_size/(1<<30))+tr("GB"):
                (file_size>(1<<20))?
                QString::number(file_size/(1<<20))+tr("MB"):
                    (file_size>(1<<10))?
                    QString::number(file_size/(1<<10))+tr("KB"):
                        QString::number(file_size));
        QTableWidgetItem *item3 = new QTableWidgetItem(QString(filename));
        item0->setFlags(item0->flags() ^ Qt::ItemIsEditable);
        item1->setFlags(item1->flags() ^ Qt::ItemIsEditable);
        item2->setFlags(item2->flags() ^ Qt::ItemIsEditable);
        item3->setFlags(item3->flags() ^ Qt::ItemIsEditable);
        ui->tableWidgetQuarantine->setColumnWidth(3, width*8);
        ui->tableWidgetQuarantine->setItem(ui->tableWidgetQuarantine->rowCount()-1,0, item0);
        ui->tableWidgetQuarantine->setItem(ui->tableWidgetQuarantine->rowCount()-1,1, item1);
        ui->tableWidgetQuarantine->setItem(ui->tableWidgetQuarantine->rowCount()-1,2, item2);
        ui->tableWidgetQuarantine->setItem(ui->tableWidgetQuarantine->rowCount()-1,3, item3);
    }
    ui->tableWidgetQuarantine->setSortingEnabled(true);
    ui->tableWidgetQuarantine->sortByColumn(1, Qt::DescendingOrder);
    ui->tableWidgetQuarantine->setSortingEnabled(false);
}

void MainWindow::updateDbQuarantine(QByteArray quarantine_name, quint32 timestamp, quint64 file_size, QByteArray file_name, quint8 verified){
    QSqlQuery query;
    query.prepare("INSERT OR REPLACE INTO quarantine ( quarantine_name , timestamp, file_size, file_name, verified ) VALUES ( :quarantine_name1 , :timestamp1, :file_size1, :file_name1, :verified1 );");
    query.bindValue(":quarantine_name1", QString(quarantine_name));
    query.bindValue(":timestamp1", timestamp);
    query.bindValue(":file_size1", file_size);
    query.bindValue(":file_name1", QString(file_name));
    query.bindValue(":verified1", verified);
    query.exec();
}

void MainWindow::updateQuaramtineCount(quint32 timestamp){
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO counts_table(timestamp, state, num) VALUES (:timestamp1, 3, 0);");
    query.bindValue(":timestamp1", timestamp);
    query.exec();
    query.prepare("UPDATE counts_table SET num = num + 1 WHERE timestamp = :timestamp1 AND state = 3 ;");
    query.bindValue(":timestamp1", timestamp);
    query.exec();
}

void MainWindow::updateNewEventsCount(){
    QSqlQuery query;
    query.prepare("SELECT count(*) FROM found WHERE alreadyread = 0;");
    query.exec();
    if(query.next()){
        qint64 num = (qint64)query.value(0).toInt();
        if(num)
            ui->labelNumBlockedAttacksVal->setText(tr("<a href=\"newevents\">")+QString::number(num)+tr("</a>"));
        else
            ui->labelNumBlockedAttacksVal->setText(tr("0"));
    }
}

void MainWindow::rand_bytes(quint32 len, QByteArray *out){
    (*out) = QByteArray();
    for(quint64 i = 0; i < (len/4); i++){
        quint32 num =
#if QT_VERSION >= 0x050a00
        QRandomGenerator::global()->generate();
#else
        qrand();
#endif
        (*out).append((quint8)(num & 0xff));
        (*out).append((quint8)((num & 0xff00) >> 8));
        (*out).append((quint8)((num & 0xff0000) >> 16));
        (*out).append((quint8)((num & 0xff000000) >> 24));
    }
    for(quint64 i = 0; i < (len%4); i++)
        (*out).append((quint8)(
#if QT_VERSION >= 0x050a00
        QRandomGenerator::global()->generate()
#else
        qrand()
#endif
        & 0xff));
}

void MainWindow::new_quarantiner(QByteArray in){
    QByteArray name;
    rand_bytes(24, &name);
    QFileInfo qfd(getValDB("quarantinefilesdirectory"));
    if(!qfd.exists())
        QDir().mkpath(qfd.absoluteFilePath());
    Quarantiner *q = new Quarantiner(in, qfd.absoluteFilePath().toLocal8Bit(), name);
    queue.enqueue(q);
    queue_up();
}

void MainWindow::queue_up(){
    if(!queue.length())
        return;
    foreach(QThread *th, threads_list){
        if(!th->isRunning()){
            Quarantiner *q = queue.dequeue();
            q->moveToThread(th);
            connect(th, &QThread::started, q, &Quarantiner::process);
            connect(q, &Quarantiner::remove, listerQuarantine, &ListerQuarantine::add_file);
            connect(q, &Quarantiner::finished, th, &QThread::quit);
            connect(q, &Quarantiner::finished, q, &Quarantiner::deleteLater);
            connect(th, &QThread::finished, this, &MainWindow::queue_up);
            connect(q, &Quarantiner::updateDbQuarantine, this, &MainWindow::updateDbQuarantine);
            connect(q, &Quarantiner::updateQuaramtineCount, this, &MainWindow::updateQuaramtineCount);
            th->start();
            break;
        }
    }
}

void MainWindow::errorMsg(QString msg, bool enable_exit){
#ifdef CLAMONE_DEBUG
    Q_UNUSED(enable_exit)
    qDebug() << "Error: " << msg;
#else
    QMessageBox messageBox;
    messageBox.critical(0, "Error", tr("An error has occurred: ")+msg);
    if(enable_exit)
        exitProgram(1);
#endif


}

void MainWindow::exitProgram(int ret){
    procKill();
    QTimer::singleShot(5000, [=]() { exit(ret); });
    QTimer::singleShot(250, [=]() { qApp->quit(); });
    qApp->quit();
}

qint64 MainWindow::initializeEventsFoundTableWidget(qint64 page, bool reset_position){
    qint64 num = 0;
    qint64 entriesperpage = getEntriesPerPage();
    int orig_vert = ui->tableWidgetEventFound->verticalScrollBar()->value();
    int orig_hori = ui->tableWidgetEventFound->horizontalScrollBar()->value();

    QSqlQuery query;
    updateNewEventsCount();

    query.prepare("SELECT count(*) FROM found;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > 0){
            if(entriesperpage*(page+1) > num)
                ui->labelEventFoundPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                ui->labelEventFoundPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            ui->labelEventFoundPagePosition->setText(tr("0 - 0 (0 entries total)"));
            return 0;
        }
    }

    query.prepare("SELECT * FROM found ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(ui->tableWidgetEventFound->rowCount())
        ui->tableWidgetEventFound->removeRow(0);

    ui->tableWidgetEventFound->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);
    while(query.next()){
        qlonglong ts = query.value(0).toLongLong();
        QString message = query.value(1).toString();
        bool existsonfs = (query.value(3).toString() == "1");
        QString filename = query.value(4).toString();
        QLabel *labelTimestamp = new QLabel();
        QTableWidgetItem *itemTimestamp = new QTableWidgetItem();
        QLabel *labelMessage = new QLabel();
        QTableWidgetItem *itemMessage = new QTableWidgetItem();
        QWidget *widgetButtons = new QWidget();
        QTableWidgetItem *itemButtons = new QTableWidgetItem();

        int currentRowNum = ui->tableWidgetEventFound->rowCount();
        ui->tableWidgetEventFound->insertRow(currentRowNum);
        ui->tableWidgetEventFound->setItem(currentRowNum, 0, itemTimestamp);
        ui->tableWidgetEventFound->setCellWidget(currentRowNum, 0, labelTimestamp);
        ui->tableWidgetEventFound->setItem(currentRowNum, 1, itemMessage);
        ui->tableWidgetEventFound->setCellWidget(currentRowNum, 1, labelMessage);
        ui->tableWidgetEventFound->setItem(currentRowNum, 2, itemButtons);
        ui->tableWidgetEventFound->setCellWidget(currentRowNum, 2, widgetButtons);

        labelTimestamp->setText(QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP"));
        labelMessage->setText(message);

        if(existsonfs){
            labelTimestamp->setStyleSheet("background-color: #FFC0C0;");
            labelMessage->setStyleSheet("background-color: #FFC0C0;");
            widgetButtons->setStyleSheet("background-color: #FFC0C0;");
            itemButtons->setText(QString::number((quint64)itemButtons, 16));
            QHBoxLayout *layout = new QHBoxLayout();
            layout->setSpacing(0);
            layout->setContentsMargins(0, 0, 0, 0);

            QPushButton *button_q = new QPushButton(tr("Quarantine"));
            button_q->setFocusPolicy(Qt::NoFocus);
            connect(button_q, &QPushButton::clicked, [=](){
                qDebug() << "button_q clicked: " << filename;
                new_quarantiner(filename.toLocal8Bit());
            });

            QPushButton *button_e = new QPushButton(tr("Exception"));
            button_e->setFocusPolicy(Qt::NoFocus);
            connect(button_e, &QPushButton::clicked, [=](){
                QSqlQuery queryButton;
                qDebug() << "button_e clicked: " << filename;
                configLaunch();
                emit addExclusionClamdconf(filename.toLocal8Bit());
                queryButton.prepare("UPDATE found SET existsonfs = 0 WHERE timestamp = :timestamp1 AND filename = :filename1 ;");
                queryButton.bindValue(":timestamp1", ts);
                queryButton.bindValue(":filename1", filename);
                queryButton.exec();
                initializeEventsFoundTableWidget(page, false);
                allHide();
            });

            QPushButton *button_i = new QPushButton(tr("Ignore"));
            button_i->setFocusPolicy(Qt::NoFocus);
            connect(button_i, &QPushButton::clicked, [=](){
                QSqlQuery queryButton;
                queryButton.prepare("UPDATE found SET existsonfs = 0 WHERE timestamp = :timestamp1 AND filename = :filename1 ;");
                queryButton.bindValue(":timestamp1", ts);
                queryButton.bindValue(":filename1", filename);
                queryButton.exec();
                initializeEventsFoundTableWidget(page, false);
            });

            widgetButtons->setLayout(layout);
            layout->addWidget(button_q);
            layout->addWidget(button_e);
            layout->addWidget(button_i);
        }else{
            labelTimestamp->setStyleSheet("background-color: #C0FFC0;");
            labelMessage->setStyleSheet("background-color: #C0FFC0;");
            widgetButtons->setStyleSheet("background-color: #C0FFC0;");
        }
        itemButtons->setSizeHint(widgetButtons->sizeHint());
    }
    ui->tableWidgetEventFound->resizeColumnToContents(0);
    ui->tableWidgetEventFound->resizeColumnToContents(1);
    ui->tableWidgetEventFound->resizeColumnToContents(2);
    if(reset_position){
        ui->tableWidgetEventFound->horizontalScrollBar()->setValue(0);
        ui->tableWidgetEventFound->verticalScrollBar()->setValue(0);
    }else{
        ui->tableWidgetEventFound->horizontalScrollBar()->setValue(orig_hori);
        ui->tableWidgetEventFound->verticalScrollBar()->setValue(orig_vert);
    }
    return num;
}

qint64 MainWindow::initializeEventsQuarantinedTableWidget(qint64 page){
    qint64 num = 0;
    qint64 entriesperpage = getEntriesPerPage();
    qint64 width = 100;

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM quarantine_log;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > 0){
            if(entriesperpage*(page+1) > num)
                ui->labelEventQuarantinedPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                ui->labelEventQuarantinedPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            ui->labelEventQuarantinedPagePosition->setText(tr("0 - 0 (0 entries total)"));
            return 0;
        }
    }

    query.prepare("SELECT * FROM quarantine_log ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(ui->tableWidgetEventQuarantined->rowCount())
        ui->tableWidgetEventQuarantined->removeRow(0);

    ui->tableWidgetEventQuarantined->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);
    while(query.next()){
        QTableWidgetItem *item = new QTableWidgetItem(query.value(1).toString());
        if(query.value(1).toString().length() > width)
            width = query.value(1).toString().length();
        ui->tableWidgetEventQuarantined->setColumnWidth(1, width*8);
        ui->tableWidgetEventQuarantined->insertRow(ui->tableWidgetEventQuarantined->rowCount());
        ui->tableWidgetEventQuarantined->setItem(ui->tableWidgetEventQuarantined->rowCount()-1,0,new QTableWidgetItem(
            QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP")
        ));
        ui->tableWidgetEventQuarantined->setItem(ui->tableWidgetEventQuarantined->rowCount()-1,1, item);
    }
    ui->tableWidgetEventQuarantined->resizeColumnToContents(1);
    ui->tableWidgetEventQuarantined->horizontalScrollBar()->setValue(0);
    ui->tableWidgetEventQuarantined->verticalScrollBar()->setValue(0);
    return num;
}

void MainWindow::detectedThreatListener(QString msg, QString filename){
    QTimer::singleShot(250, [=]() {
        trayIcon->showMessage(tr("Clam One - THREAT DETECTED"), msg, QIcon(QPixmap(":/images/expl_16.png")));
    });
    if(getValDB("enablequarantine") == "yes")
        new_quarantiner(filename.toLocal8Bit());
}

void MainWindow::setEnabledQuarantine(bool state){
    ui->tableWidgetQuarantine->setEnabled(state);
    ui->pushButtonQuarantineDelete->setEnabled(state);
    ui->pushButtonQuarantineUnQuarantine->setEnabled(state);
    ui->tableWidgetEventQuarantined->setEnabled(state);
    if(state){
        ui->tableWidgetQuarantine->setStyleSheet("background-color: #ffffff;");
        ui->tableWidgetEventQuarantined->setStyleSheet("background-color: #ffffff;");
    }else{
        ui->tableWidgetQuarantine->setStyleSheet("background-color: #eeeeee;");
        ui->tableWidgetEventQuarantined->setStyleSheet("background-color: #eeeeee;");
    }
}

quint64 MainWindow::getEntriesPerPage(){
    qint64 entriesperpage = 40;
    QString res = getValDB("entriesperpage");
    if(!res.isEmpty()){
        bool ok = false;
        entriesperpage = res.toInt(&ok);
        if(!ok || entriesperpage > 1000000 || entriesperpage < 1)
            entriesperpage = 40;
    }
    return entriesperpage;
}

void MainWindow::setScanActive(bool state){
    isScanActive = state;
    if(!state)
        procKill();
}

void MainWindow::initScanProcess(QStringList listWidgetToStringList){
    p->start("clamdscan", QStringList() << "-v" << "--stdout" << "--fdpass" << listWidgetToStringList);
    emit sigProcessReadyRead("Scan started...\n");
#ifdef CLAMONE_COUNT_ITEMS_SCANNED
    QTimer::singleShot(250, [=]() {
        QSqlQuery query;
        quint32 ts;
        quint64 count = 0;
        countTotalScanItems(listWidgetToStringList, &count);

        ts = (quint32)time(NULL);
        query.prepare("INSERT OR IGNORE INTO counts_table(timestamp, state, num) VALUES (:timestamp1, 1, 0);");
        query.bindValue(":timestamp1", ts);
        query.exec();
        query.prepare("UPDATE counts_table SET num = num + :num1 WHERE timestamp = :timestamp1 AND state = 1 ;");
        query.bindValue(":timestamp1", ts);
        query.bindValue(":num1", count);
        query.exec();
    });
#endif //CLAMONE_COUNT_ITEMS_SCANNED
}

void MainWindow::processReadyRead(){
    emit sigProcessReadyRead(p->readAll());
}

void MainWindow::allShow(){
    setVisible(true);
    setWindowState(windowState() & ~Qt::WindowMinimized);
    if(isScanActive && p && p->state() != QProcess::NotRunning)
        scanDialog->setVisible(true);
}

void MainWindow::iconActivated(QSystemTrayIcon::ActivationReason reason){
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        if(isVisible()){
            allHide();
        }else{
            allShow();
            ui->listWidget->setCurrentRow(ClamOneMainStackOrder::Scan);
        }
        break;
    default:
        ;
    }
}

void MainWindow::on_labelScanQuickScan_linkActivated(const QString &link){
    Q_UNUSED( link )
    if(!isScanActive)
        scanDialog->initializeQuickScan(isScanActive);
    else
        scanDialog->show();
}

void MainWindow::on_labelScanDeepScan_linkActivated(const QString &link){
    Q_UNUSED( link )
    if(!isScanActive)
        scanDialog->initializeDeepScan(isScanActive);
    else
        scanDialog->show();
}

void MainWindow::on_labelUpdateClickUpdateDefs_linkActivated(const QString &link){
    Q_UNUSED(link)
    int rClamd = -1, rFresh = -1, rClamonacc = -1;
    ckProc(&rClamd, &rFresh, &rClamonacc);
    if(rFresh > 0){
        QProcess::execute(tr("pkexec kill -USR1 ")+QString::number(rFresh));
        allHide();
    }
}

void MainWindow::on_labelSetupAccessPrefs_linkActivated(const QString &link){
    Q_UNUSED(link)
    configLaunch();
}

void MainWindow::on_labelNumBlockedAttacksVal_linkActivated(const QString &link){
    Q_UNUSED( link )
    QSqlQuery query;
    query.prepare("UPDATE OR IGNORE found SET alreadyread = 1 WHERE alreadyread = 0;");
    query.exec();

    initializeEventsFoundTableWidget(intEventFoundPageNumber, true);
    ui->listWidget->setCurrentRow(ClamOneMainStackOrder::Log);
    ui->comboBoxLog->setCurrentIndex(ClamOneEventsStackOrder::EventFound);
    ui->stackedWidgetEvents->setCurrentIndex(ClamOneEventsStackOrder::EventFound);
    updateNewEventsCount();
}

void MainWindow::on_labelHelpTitleSubtitle_linkActivated(const QString &link){
    Q_UNUSED(link)
    aboutLaunch();
}

void MainWindow::on_pushButtonEventGeneralPageForward_clicked(){
    qint64 entriesperpage = getEntriesPerPage();

    qint64 num = initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
    if((qint64)(entriesperpage*(intEventGeneralPageNumber+1)) <= num){
        if(intEventGeneralPageNumber<0xffffffff)
            intEventGeneralPageNumber++;
        else
            intEventGeneralPageNumber = 0;
    }
    initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
}

void MainWindow::on_pushButtonEventGeneralPageBack_clicked(){
    if(intEventGeneralPageNumber>0)
        intEventGeneralPageNumber--;
    initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
}

void MainWindow::on_pushButtonEventGeneralPageBegining_clicked(){
    intEventGeneralPageNumber = 0;
    initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
}

void MainWindow::on_pushButtonEventGeneralPageEnd_clicked(){
    qint64 num = -1;
    qint64 entriesperpage = getEntriesPerPage();

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM general;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > (entriesperpage-1)){
            intEventGeneralPageNumber = ((num%entriesperpage)==0)?(num/entriesperpage)-1:num/entriesperpage;
            initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
        }else if(num > 0){
            intEventGeneralPageNumber = 0;
            initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
        }
    }
}

void MainWindow::on_pushButtonMessagesPageForward_clicked(){
    qint64 entriesperpage = getEntriesPerPage();

    qint64 num = initializeMessagesTableWidget(intMessagesPageNumber);
    if((qint64)(entriesperpage*(intMessagesPageNumber+1)) <= num){
        if(intMessagesPageNumber<0xffffffff)
            intMessagesPageNumber++;
        else
            intMessagesPageNumber = 0;
    }
    initializeMessagesTableWidget(intMessagesPageNumber);

}

void MainWindow::on_pushButtonMessagesPageBack_clicked(){
    if(intMessagesPageNumber>0)
        intMessagesPageNumber--;
    initializeMessagesTableWidget(intMessagesPageNumber);
}

void MainWindow::on_pushButtonMessagesPageBegining_clicked(){
    intMessagesPageNumber = 0;
    initializeMessagesTableWidget(intMessagesPageNumber);
}

void MainWindow::on_pushButtonMessagesPageEnd_clicked(){
    qint64 num = -1;
    qint64 entriesperpage = getEntriesPerPage();

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM messages;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > (entriesperpage-1)){
            intMessagesPageNumber = ((num%entriesperpage)==0)?(num/entriesperpage)-1:num/entriesperpage;
            initializeMessagesTableWidget(intMessagesPageNumber);
        }else{
            intMessagesPageNumber = 0;
            initializeMessagesTableWidget(intMessagesPageNumber);
        }
    }
}

void MainWindow::on_pushButtonQuarantineDelete_clicked(){
    if(ui->tableWidgetQuarantine->selectedItems().isEmpty())
        return;
    QString quarantineNameToDelete = ui->tableWidgetQuarantine->selectedItems().at(0)->text();
    QString fileNameToUnQuarantine = ui->tableWidgetQuarantine->selectedItems().at(3)->text();
    quint32 timestamp = 0;
    QSqlQuery query;
    query.prepare("DELETE FROM quarantine WHERE quarantine_name = :quarantine_name1 ;");
    query.bindValue(":quarantine_name1", quarantineNameToDelete);
    query.exec();
    QString path = getValDB("quarantinefilesdirectory");
    QFile qfi(path+tr("/")+quarantineNameToDelete);
    if(qfi.exists() && QFileInfo(path+tr("/")+quarantineNameToDelete).isFile()){
        qfi.remove();
    }
    updateQuarantineDirectoryUi("");
    markQuarantineDeleteQ(quarantineNameToDelete.toLocal8Bit()+": ("+fileNameToUnQuarantine.toLocal8Bit()+")");
    timestamp = (quint32)time(NULL);
    query.prepare("INSERT OR IGNORE INTO counts_table(timestamp, state, num) VALUES (:timestamp1, 4, 0);");
    query.bindValue(":timestamp1", timestamp);
    query.exec();
    query.prepare("UPDATE counts_table SET num = num + 1 WHERE timestamp = :timestamp1 AND state = 4 ;");
    query.bindValue(":timestamp1", timestamp);
    query.exec();
}

void MainWindow::on_pushButtonQuarantineUnQuarantine_clicked(){
    if(ui->tableWidgetQuarantine->selectedItems().isEmpty())
        return;
    QString path = getValDB("quarantinefilesdirectory");
    QString quarantineNameToDelete = ui->tableWidgetQuarantine->selectedItems().at(0)->text();
    QString fileNameToUnQuarantine = ui->tableWidgetQuarantine->selectedItems().at(3)->text();
    QFileInfo qfi(fileNameToUnQuarantine);
    if(qfi.exists()){
        if(qfi.isFile()){
            qDebug() << "A file already exists at " << fileNameToUnQuarantine;
        }else if(qfi.isDir()){
            qDebug() << "A directory exists at " << fileNameToUnQuarantine;
        }else if(qfi.isSymLink()){
            qDebug() << "A symbolic link exists at " << fileNameToUnQuarantine;
        }
        return;
    }
    QFile qf(fileNameToUnQuarantine);
    if(!qf.open(QFile::WriteOnly)){
        qDebug() << "Cannot re-create and write to file at location " << fileNameToUnQuarantine;
        return;
    }

    QFile quarantine_file(path+tr("/")+quarantineNameToDelete);
    if(!quarantine_file.open(QFile::ReadOnly)){
        qDebug() << "Cannot read quarantine file: " << (path+tr("/")+quarantineNameToDelete);
        qf.close();
        return;
    }
    QByteArray test_filename;
    QByteArray fileContentsBytes = QAES().unlock(quarantine_file.readAll(), &test_filename);
    quarantine_file.close();
    if(fileContentsBytes.isEmpty() || test_filename != fileNameToUnQuarantine.toLocal8Bit()){
        qDebug() << "Cannot read quarantine file: " << (path+tr("/")+quarantineNameToDelete);
        qf.close();
        return;
    }
    qf.write(fileContentsBytes);
    qf.close();
    on_pushButtonQuarantineDelete_clicked();
    markQuarantineUnQ(fileNameToUnQuarantine.toLocal8Bit());
}

void MainWindow::on_pushButtonSchedule_clicked(){
    add_new_schedule();
    schedule_detected_change();
}

void MainWindow::add_new_schedule(bool enable, QString schedule_name,
        QString schedule_minute, QString schedule_hour, QString schedule_day_month,
        QString schedule_month, QString schedule_day_week, QStringList schedule_stringlist
    ){
    QListWidgetItem *item = new QListWidgetItem();
    QWidget *widget = new QWidget();
    item->setText(QString::number((quint64)item, 16));
    QHBoxLayout *layout = new QHBoxLayout();
    layout->setSpacing(0);

    //0
    QLabel *labelDelete = new QLabel(
                "<a href=\""+QString::number((quint64)item, 16)+"\">X</a> ");
    labelDelete->setToolTip(tr("Click to delete this schedule entry"));

    //1
    QCheckBox *checkBoxEnable = new QCheckBox();
    checkBoxEnable->setText(enable?tr("enabled"):tr("disabled"));
    checkBoxEnable->setChecked(enable);
    checkBoxEnable->setToolTip(tr("Should this schedule entry be enabled"));
    connect(checkBoxEnable, &QCheckBox::stateChanged,
    [=](bool checkboxToggled){
        checkBoxEnable->setText(checkboxToggled?tr("enabled"):tr("disabled"));
        schedule_detected_change();
    });

    //2
    QLineEdit *lineEditName = new QLineEdit();
    lineEditName->setMaximumWidth(100);
    QFont font = lineEditName->font();
    font.setStyleHint(QFont::Monospace);
    lineEditName->setFont(font);
    lineEditName->setToolTip(tr("Name of this schedule entry"));
    if(schedule_name.isEmpty())
        lineEditName->setText(QString::number((quint64)item, 16));
    else
        lineEditName->setText(schedule_name);
    connect(lineEditName, static_cast<void(QLineEdit::*)(const QString &)>(&QLineEdit::textEdited),
    [=](const QString &lineEditNameText){
        Q_UNUSED(lineEditNameText)
        schedule_detected_change();
    });

    //3
    QLineEdit *lineEditMinute = new QLineEdit();
    lineEditMinute->setMaximumWidth(60);
    lineEditMinute->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    font = lineEditMinute->font();
    font.setStyleHint(QFont::Monospace);
    lineEditMinute->setFont(font);
    lineEditMinute->setToolTip(tr("Crontab style minute field"));
    lineEditMinute->setText(schedule_minute);
    connect(lineEditMinute, static_cast<void(QLineEdit::*)(const QString &)>(&QLineEdit::textEdited),
    [=](const QString &lineEditMinuteText){
        Q_UNUSED(lineEditMinuteText)
        schedule_detected_change();
    });

    //4
    QLineEdit *lineEditHour = new QLineEdit();
    lineEditHour->setMaximumWidth(60);
    lineEditHour->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    font = lineEditHour->font();
    font.setStyleHint(QFont::Monospace);
    lineEditHour->setFont(font);
    lineEditHour->setToolTip(tr("Crontab style hour field"));
    lineEditHour->setText(schedule_hour);
    connect(lineEditHour, static_cast<void(QLineEdit::*)(const QString &)>(&QLineEdit::textEdited),
    [=](const QString &lineEditHourText){
        Q_UNUSED(lineEditHourText)
        schedule_detected_change();
    });

    //5
    QLineEdit *lineEditDayMonth = new QLineEdit();
    lineEditDayMonth->setMaximumWidth(60);
    lineEditDayMonth->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    font = lineEditDayMonth->font();
    font.setStyleHint(QFont::Monospace);
    lineEditDayMonth->setFont(font);
    lineEditDayMonth->setToolTip(tr("Crontab style day of month field"));
    lineEditDayMonth->setText(schedule_day_month);
    connect(lineEditDayMonth, static_cast<void(QLineEdit::*)(const QString &)>(&QLineEdit::textEdited),
    [=](const QString &lineEditDayMonthText){
        Q_UNUSED(lineEditDayMonthText)
        schedule_detected_change();
    });

    //6
    QLineEdit *lineEditMonth = new QLineEdit();
    lineEditMonth->setMaximumWidth(60);
    lineEditMonth->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    font = lineEditMonth->font();
    font.setStyleHint(QFont::Monospace);
    lineEditMonth->setFont(font);
    lineEditMonth->setToolTip(tr("Crontab style month field"));
    lineEditMonth->setText(schedule_month);
    connect(lineEditMonth, static_cast<void(QLineEdit::*)(const QString &)>(&QLineEdit::textEdited),
    [=](const QString &lineEditMonthText){
        Q_UNUSED(lineEditMonthText)
        schedule_detected_change();
    });

    //7
    QLineEdit *lineEditDayWeek = new QLineEdit();
    lineEditDayWeek->setMaximumWidth(60);
    lineEditDayWeek->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    font = lineEditDayWeek->font();
    font.setStyleHint(QFont::Monospace);
    lineEditDayWeek->setFont(font);
    lineEditDayWeek->setToolTip(tr("Crontab style day of week field"));
    lineEditDayWeek->setText(schedule_day_week);
    connect(lineEditDayWeek, static_cast<void(QLineEdit::*)(const QString &)>(&QLineEdit::textEdited),
    [=](const QString &lineEditDayWeekText){
        Q_UNUSED(lineEditDayWeekText)
        schedule_detected_change();
    });

    //8
    QStringListWidget *stringlistWidget = new QStringListWidget();
    font = stringlistWidget->font();
    font.setStyleHint(QFont::Monospace);
    stringlistWidget->setFont(font);
    stringlistWidget->setToolTip(tr("List of Files/Directories to scan"));
    stringlistWidget->setQStringList(schedule_stringlist);
    connect(stringlistWidget, &QStringListWidget::stringlistChange,
    [=](){
        schedule_detected_change();
    });

    //9
    QPushButton *addFileWidget = new QPushButton();
    addFileWidget->setText(tr("Add File"));
    font = addFileWidget->font();
    font.setStyleHint(QFont::Monospace);
    addFileWidget->setFont(font);
    addFileWidget->setToolTip(tr("Add Files to the list"));
    connect(addFileWidget, &QPushButton::clicked,
    [=](){
        QString addfile = QFileDialog::getOpenFileName(Q_NULLPTR, tr("Add File"), Q_NULLPTR, Q_NULLPTR);
        if(!addfile.isEmpty()){
            QStringList tmplist = stringlistWidget->getQStringList();
            tmplist.append(addfile);
            stringlistWidget->setQStringList(tmplist);
        }
        schedule_detected_change();
    });

    //10
    QPushButton *addDirWidget = new QPushButton();
    addDirWidget->setText(tr("Add Dir"));
    font = addDirWidget->font();
    font.setStyleHint(QFont::Monospace);
    addDirWidget->setFont(font);
    addDirWidget->setToolTip(tr("Add Directories to the list"));
    connect(addDirWidget, &QPushButton::clicked,
    [=](){
        QString adddir = QFileDialog::getExistingDirectory(Q_NULLPTR, tr("Add Dir"), Q_NULLPTR, Q_NULLPTR);
        if(!adddir.isEmpty()){
            QStringList tmplist = stringlistWidget->getQStringList();
            tmplist.append(adddir);
            stringlistWidget->setQStringList(tmplist);
        }
        schedule_detected_change();
    });

    QSpacerItem *hsp = new QSpacerItem(20, 40, QSizePolicy::Expanding, QSizePolicy::Expanding);

    widget->setLayout(layout);
    layout->addWidget(labelDelete); //0
    layout->addWidget(checkBoxEnable); //1
    layout->addWidget(lineEditName); //2
    layout->addWidget(lineEditMinute); //3
    layout->addWidget(lineEditHour); //4
    layout->addWidget(lineEditDayMonth); //5
    layout->addWidget(lineEditMonth); //6
    layout->addWidget(lineEditDayWeek); //7
    layout->addWidget(addFileWidget); //9
    layout->addWidget(addDirWidget); //10
    layout->addWidget(stringlistWidget); //8
    layout->addItem(hsp);
    connect(labelDelete, &QLabel::linkActivated, this, &MainWindow::removeScheduleItemAt);
    ui->listWidgetSchedule->addItem(item);
    ui->listWidgetSchedule->setItemWidget(item, widget);
    item->setSizeHint(widget->sizeHint());
}

void MainWindow::add_new_schedule(){
    add_new_schedule(false, "", "0", "17", "*", "*", "*", QStringList());
    schedule_detected_change();
}

void MainWindow::schedule_detected_change(){
    QSqlQuery query;
    QSqlDatabase::database().transaction();
    query.prepare("DELETE FROM schedule;");
    query.exec();
    for(int i = 0; i < ui->listWidgetSchedule->count(); i++){
        QListWidgetItem *item = ui->listWidgetSchedule->item(i);
        QWidget *widget = ui->listWidgetSchedule->itemWidget(item);
        QLayout *layout = widget->layout();

        //QLabel *labelDelete = static_cast<QLabel *>(layout->itemAt(0)->widget());
        QCheckBox *checkBoxEnable = static_cast<QCheckBox *>(layout->itemAt(1)->widget());
        QLineEdit *lineEditName = static_cast<QLineEdit *>(layout->itemAt(2)->widget());
        QLineEdit *lineEditMinute = static_cast<QLineEdit *>(layout->itemAt(3)->widget());
        QLineEdit *lineEditHour = static_cast<QLineEdit *>(layout->itemAt(4)->widget());
        QLineEdit *lineEditDayMonth = static_cast<QLineEdit *>(layout->itemAt(5)->widget());
        QLineEdit *lineEditMonth = static_cast<QLineEdit *>(layout->itemAt(6)->widget());
        QLineEdit *lineEditDayWeek = static_cast<QLineEdit *>(layout->itemAt(7)->widget());
        //QPushButton *addFileWidget = static_cast<QPushButton *>(layout->itemAt(8)->widget());
        //QPushButton *addDirWidget = static_cast<QPushButton *>(layout->itemAt(9)->widget());
        QStringListWidget *stringlistWidget = static_cast<QStringListWidget *>(layout->itemAt(10)->widget());

        bool ok1, ok2, ok3, isValidSchedule = true;
        int num1, num2, num3;
        parseScheduleMinutes(lineEditMinute->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(ok1)
            lineEditMinute->setStyleSheet("background-color: #cbfbd1;");
        else{
            lineEditMinute->setStyleSheet("background-color: #fbc2c1;");
            isValidSchedule = false;
        }
        parseScheduleHours(lineEditHour->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(ok1)
            lineEditHour->setStyleSheet("background-color: #cbfbd1;");
        else{
            lineEditHour->setStyleSheet("background-color: #fbc2c1;");
            isValidSchedule = false;
        }
        parseScheduleDayMonth(lineEditDayMonth->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(ok1)
            lineEditDayMonth->setStyleSheet("background-color: #cbfbd1;");
        else{
            lineEditDayMonth->setStyleSheet("background-color: #fbc2c1;");
            isValidSchedule = false;
        }
        parseScheduleMonth(lineEditMonth->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(ok1)
            lineEditMonth->setStyleSheet("background-color: #cbfbd1;");
        else{
            lineEditMonth->setStyleSheet("background-color: #fbc2c1;");
            isValidSchedule = false;
        }
        parseScheduleDayWeek(lineEditDayWeek->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(ok1)
            lineEditDayWeek->setStyleSheet("background-color: #cbfbd1;");
        else{
            lineEditDayWeek->setStyleSheet("background-color: #fbc2c1;");
            isValidSchedule = false;
        }

        bool enable = checkBoxEnable->isChecked();
        QString name = lineEditName->text();
        QString minute = lineEditMinute->text();
        QString hour = lineEditHour->text();
        QString daymonth = lineEditDayMonth->text();
        QString month = lineEditMonth->text();
        QString dayweek = lineEditDayWeek->text();
        QByteArray stringlist;
        foreach(QString line, stringlistWidget->getQStringList()){
            stringlist.append(line.toLocal8Bit());
            stringlist.append(QByteArray("\x00", 1));
        }
        if(stringlist.isEmpty())
            isValidSchedule = false;
        if(checkBoxEnable->isChecked())
            widget->setStyleSheet("background-color: #cbfbd1;");
        else
            widget->setStyleSheet("background-color: #fbc2c1;");
        if(!isValidSchedule && checkBoxEnable->isEnabled()){
            checkBoxEnable->setChecked(false);
            checkBoxEnable->setEnabled(false);
        }else{
            checkBoxEnable->setEnabled(true);
        }

        query.prepare("INSERT OR IGNORE INTO schedule(enable, name, minute, hour, daymonth, month, dayweek, stringlist) "
                      "VALUES(:enable, :name, :minute, :hour, :daymonth, :month, :dayweek, :stringlist);");
        query.bindValue(":enable", enable?1:0);
        query.bindValue(":name", name);
        query.bindValue(":minute", minute);
        query.bindValue(":hour", hour);
        query.bindValue(":daymonth", daymonth);
        query.bindValue(":month", month);
        query.bindValue(":dayweek", dayweek);
        query.bindValue(":stringlist", stringlist);
        query.exec();
    }
    QSqlDatabase::database().commit();
}

void MainWindow::parseScheduleDayWeek(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3){
    parseScheduleBaseTime(input, ok1, num1, ok2, num2, ok3, num3, 0, 7);
}

void MainWindow::parseScheduleMonth(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3){
    parseScheduleBaseTime(input, ok1, num1, ok2, num2, ok3, num3, 1, 12);
}

void MainWindow::parseScheduleDayMonth(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3){
    parseScheduleBaseTime(input, ok1, num1, ok2, num2, ok3, num3, 1, 31);
}

void MainWindow::parseScheduleHours(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3){
    parseScheduleBaseTime(input, ok1, num1, ok2, num2, ok3, num3, 0, 23);
}

void MainWindow::parseScheduleMinutes(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3){
    parseScheduleBaseTime(input, ok1, num1, ok2, num2, ok3, num3, 0, 59);
}

void MainWindow::parseScheduleBaseTime(QString input, bool *ok1, int *num1, bool *ok2, int *num2, bool *ok3, int *num3, int limit_min, int limit_max){
    QRegularExpression re;
    QRegularExpressionMatch match;
    int tmp;

    //*	        true	-1	    false	-1	    false	-1
    re.setPattern("^\\*$");
    match = re.match(input);
    if(match.hasMatch()){
        *ok1 = true;
        *num1 = -1;
        *ok2 = false;
        *num2 = -1;
        *ok3 = false;
        *num3 = -1;
        return;
    }

    //24	    true	24	    false	-1	    false	-1
    re.setPattern("^([0-9]+)$");
    match = re.match(input);
    if(match.hasMatch()){
        tmp = match.captured(1).toInt(ok1);
        if(!*ok1 || tmp < limit_min || tmp > limit_max)
            goto bad_match;
        *num1 = tmp;
        *ok2 = false;
        *num2 = -1;
        *ok3 = false;
        *num3 = -1;
        return;
    }

    //24-32	    true	24	    true	32	    false	-1
    re.setPattern("^([0-9]+)-([0-9]+)$");
    match = re.match(input);
    if(match.hasMatch()){
        tmp = match.captured(1).toInt(ok1);
        if(!*ok1 || tmp < limit_min || tmp > limit_max)
            goto bad_match;
        *num1 = tmp;
        tmp = match.captured(2).toInt(ok2);
        if(!*ok2 || tmp < limit_min || tmp > limit_max || (*num1 >= tmp))
            goto bad_match;
        *num2 = tmp;
        *ok3 = false;
        *num3 = -1;
        return;
    }

    //*/2	    true	-1	    false	-1	    true	2
    re.setPattern("^\\*/([0-9]+)$");
    match = re.match(input);
    if(match.hasMatch()){
        *ok1 = true;
        *num1 = -1;
        *ok2 = false;
        *num2 = -1;
        tmp = match.captured(1).toInt(ok3);
        if(!*ok3 || tmp < 1 || tmp > limit_max)
            goto bad_match;
        *num3 = tmp;
        return;
    }

    //24/2	    true	24	    false	-1	    true	2
    re.setPattern("^([0-9]+)/([0-9]+)$");
    match = re.match(input);
    if(match.hasMatch()){
        tmp = match.captured(1).toInt(ok1);
        if(!*ok1 || tmp < limit_min || tmp > limit_max)
            goto bad_match;
        *num1 = tmp;
        *ok2 = false;
        *num2 = -1;
        tmp = match.captured(2).toInt(ok3);
        if(!*ok3 || tmp < 1 || tmp > limit_max)
            goto bad_match;
        *num3 = tmp;
        return;
    }

    //24-32/2	true	24	    true	32	    true	2
    re.setPattern("^([0-9]+)-([0-9]+)/([0-9]+)$");
    match = re.match(input);
    if(match.hasMatch()){
        tmp = match.captured(1).toInt(ok1);
        if(!*ok1 || tmp < limit_min || tmp > limit_max)
            goto bad_match;
        *num1 = tmp;
        tmp = match.captured(2).toInt(ok2);
        if(!*ok2 || tmp < limit_min || tmp > limit_max || (*num1 >= tmp))
            goto bad_match;
        *num2 = tmp;
        tmp = match.captured(3).toInt(ok3);
        if(!*ok3 || tmp < 1 || tmp > limit_max)
            goto bad_match;
        *num3 = tmp;
        return;
    }

bad_match:
    *ok1 = false;
    *num1 = -1;
    *ok2 = false;
    *num2 = -1;
    *ok3 = false;
    *num3 = -1;
}

void MainWindow::removeScheduleItemAt(const QString link){
    int list_count = ui->listWidgetSchedule->count();
    bool ok;
    qlonglong remove = link.toLongLong(&ok, 16);
    if(!ok || !list_count)
        return;
    for(int i = 0; i < ui->listWidgetSchedule->count(); i++){
        if(ui->listWidgetSchedule->item(i) == (QListWidgetItem *)remove){
            int row_num = ui->listWidgetSchedule->row((QListWidgetItem *)remove);
            ui->listWidgetSchedule->takeItem(row_num);
            schedule_detected_change();
            break;
        }
    }
}

void MainWindow::ListerQuarantineYesClicked(){
    QTimer::singleShot(250, [=]() {
        refreshFoundTableOnUpdate = true;
        initializeEventsFoundTableWidget(0);
    });
}

void MainWindow::ListerQuarantineNoClicked(){
    QTimer::singleShot(250, [=]() {
        refreshFoundTableOnUpdate = true;
        initializeEventsFoundTableWidget(0);
    });
}

void MainWindow::on_pushButtonGraphsFileScansXscaleup_clicked(){
    graphs_scaned_xscale++;
    if(graphs_scaned_xscale>0xff)
        graphs_scaned_xscale=0xff;
    initializeDateTimeLineGraphWidget(1);
}

void MainWindow::on_pushButtonGraphsFileScansXscaledown_clicked(){
    graphs_scaned_xscale--;
    if(graphs_scaned_xscale<-0xff)
        graphs_scaned_xscale=-0xff;
    initializeDateTimeLineGraphWidget(1);
}

void MainWindow::on_pushButtonGraphsFileScansXshiftup_clicked(){
    graphs_scaned_xshift += DELTA_BASE * pow(2., graphs_scaned_xscale);
    initializeDateTimeLineGraphWidget(1);
}

void MainWindow::on_pushButtonGraphsFileScansXshiftdown_clicked(){
    graphs_scaned_xshift -= DELTA_BASE * pow(2., graphs_scaned_xscale);
    if(graphs_scaned_xshift<0)
        graphs_scaned_xshift=0.0;
    initializeDateTimeLineGraphWidget(1);
}

void MainWindow::on_pushButtonGraphsFileScansResetGraph_clicked(){
    graphs_scaned_xscale=0;
    graphs_scaned_xshift=0.0;
    initializeDateTimeLineGraphWidget(1);
}

void MainWindow::on_pushButtonGraphsFileFoundXscaleup_clicked(){
    graphs_found_xscale++;
    if(graphs_found_xscale>0xff)
        graphs_found_xscale=0xff;
    initializeDateTimeLineGraphWidget(2);
}

void MainWindow::on_pushButtonGraphsFileFoundXscaledown_clicked(){
    graphs_found_xscale--;
    if(graphs_found_xscale<-0xff)
        graphs_found_xscale=-0xff;
    initializeDateTimeLineGraphWidget(2);
}

void MainWindow::on_pushButtonGraphsFileFoundXshiftup_clicked(){
    graphs_found_xshift += DELTA_BASE * pow(2., graphs_found_xscale);
    initializeDateTimeLineGraphWidget(2);
}

void MainWindow::on_pushButtonGraphsFileFoundXshiftdown_clicked(){
    graphs_found_xshift -= DELTA_BASE * pow(2., graphs_found_xscale);
    if(graphs_found_xshift<0)
        graphs_found_xshift=0.0;
    initializeDateTimeLineGraphWidget(2);
}

void MainWindow::on_pushButtonGraphsFileFoundResetGraph_clicked(){
    graphs_found_xscale=0;
    graphs_found_xshift=0.0;
    initializeDateTimeLineGraphWidget(2);
}

void MainWindow::on_pushButtonGraphsFileQuarantineXscaleup_clicked(){
    graphs_quarantine_xscale++;
    if(graphs_quarantine_xscale>0xff)
        graphs_quarantine_xscale=0xff;
    initializeDateTimeLineGraphWidget(3);
}

void MainWindow::on_pushButtonGraphsFileQuarantineXscaledown_clicked(){
    graphs_quarantine_xscale--;
    if(graphs_quarantine_xscale<-0xff)
        graphs_quarantine_xscale=-0xff;
    initializeDateTimeLineGraphWidget(3);
}

void MainWindow::on_pushButtonGraphsFileQuarantineXshiftup_clicked(){
    graphs_quarantine_xshift += DELTA_BASE * pow(2., graphs_quarantine_xscale);
    initializeDateTimeLineGraphWidget(3);
}

void MainWindow::on_pushButtonGraphsFileQuarantineXshiftdown_clicked(){
    graphs_quarantine_xshift -= DELTA_BASE * pow(2., graphs_quarantine_xscale);
    if(graphs_quarantine_xshift<0)
        graphs_quarantine_xshift=0.0;
    initializeDateTimeLineGraphWidget(3);
}

void MainWindow::on_pushButtonGraphsFileQuarantineResetGraph_clicked(){
    graphs_quarantine_xscale=0;
    graphs_quarantine_xshift=0.0;
    initializeDateTimeLineGraphWidget(3);
}

void MainWindow::on_pushButtonEventFoundPageBack_clicked(){
    if(intEventFoundPageNumber>0)
        intEventFoundPageNumber--;
    initializeEventsFoundTableWidget(intEventFoundPageNumber, true);
}

void MainWindow::on_pushButtonEventFoundPageForward_clicked(){
    qint64 entriesperpage = getEntriesPerPage();

    qint64 num = initializeEventsFoundTableWidget(intEventFoundPageNumber, true);
    if((qint64)(entriesperpage*(intEventFoundPageNumber+1)) <= num){
        if(intEventFoundPageNumber<0xffffffff)
            intEventFoundPageNumber++;
        else
            intEventFoundPageNumber = 0;
    }
    initializeEventsFoundTableWidget(intEventFoundPageNumber, true);
}

void MainWindow::on_pushButtonEventFoundPageBegining_clicked(){
    intEventFoundPageNumber = 0;
    initializeEventsFoundTableWidget(intEventFoundPageNumber, true);
}

void MainWindow::on_pushButtonEventFoundPageEnd_clicked(){
    qint64 num = -1;
    qint64 entriesperpage = getEntriesPerPage();

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM found;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > (entriesperpage-1)){
            intEventFoundPageNumber = ((num%entriesperpage)==0)?(num/entriesperpage)-1:num/entriesperpage;
        }else if(num > 0){
            intEventFoundPageNumber = 0;
        }
        initializeEventsFoundTableWidget(intEventFoundPageNumber, true);
    }
}

void MainWindow::on_pushButtonEventQuarantinedPageBack_clicked(){
    if(!ui->tableWidgetEventQuarantined->isEnabled())
        return;
    if(intEventQuarantinedPageNumber>0)
        intEventQuarantinedPageNumber--;
    initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
}

void MainWindow::on_pushButtonEventQuarantinedPageForward_clicked(){
    if(!ui->tableWidgetEventQuarantined->isEnabled())
        return;
    qint64 entriesperpage = getEntriesPerPage();

    qint64 num = initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
    if((qint64)(entriesperpage*(intEventQuarantinedPageNumber+1)) <= num){
        if(intEventQuarantinedPageNumber<0xffffffff)
            intEventQuarantinedPageNumber++;
        else
            intEventQuarantinedPageNumber = 0;
    }
    initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
}

void MainWindow::on_pushButtonEventQuarantinedPageBegining_clicked(){
    if(!ui->tableWidgetEventQuarantined->isEnabled())
        return;
    intEventQuarantinedPageNumber = 0;
    initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
}

void MainWindow::on_pushButtonEventQuarantinedPageEnd_clicked(){
    if(!ui->tableWidgetEventQuarantined->isEnabled())
        return;
    qint64 num = -1;
    qint64 entriesperpage = getEntriesPerPage();

    QSqlQuery query;
    query.prepare("SELECT count(*) FROM quarantine_log;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > (entriesperpage-1)){
            intEventQuarantinedPageNumber = ((num%entriesperpage)==0)?(num/entriesperpage)-1:num/entriesperpage;
        }else if(num > 0){
            intEventQuarantinedPageNumber = 0;
        }
        initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
    }
}

QString MainWindow::getClamdLocalSocketname(){
    QFile found(getValDB("clamdconf"));
    if(found.exists() && found.open(QIODevice::ReadOnly)){
        QTextStream in(&found);
        while (!in.atEnd()){
            QString line = in.readLine();
            if(QRegularExpression("^LocalSocket\\s+.*$").match(line).hasMatch()){
                found.close();
                found.setFileName(line.replace(QRegularExpression("^LocalSocket\\s+(.*)$"),"\\1"));
                if(found.exists() && std::experimental::filesystem::is_socket(qPrintable(line.replace(QRegularExpression("^LocalSocket\\s+(.*)$"),"\\1"))))
                    return line.replace(QRegularExpression("^LocalSocket\\s+(.*)$"),"\\1");
            }
        }
        found.close();
    }
    return QString();
}

QString MainWindow::getClamdLogFileName(){
    QRegularExpression re;
    QString logfileVar = "";
    QFile file(getValDB("clamdconf"));

    if(!file.exists())
        return QString();

    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();

    while(!file.atEnd()){
        QByteArray line = file.readLine();

        re.setPattern("^LogFile\\s+(?<LogFile>.+)\\s*$");
        if(re.match(line).hasMatch()){
            logfileVar = re.match(line).captured("LogFile");
            break;
        }
    }
    file.close();
    return logfileVar;
}

QString MainWindow::getClamdUpdateLogFileName(){
    QRegularExpression re;
    QString logfileVar = "";
    QFile file(getValDB("freshclamconf"));

    if(!file.exists())
        return QString();

    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();

    while(!file.atEnd()){
        QByteArray line = file.readLine();

        re.setPattern("^UpdateLogFile\\s+(?<UpdateLogFile>.+)\\s*$");
        if(re.match(line).hasMatch()){
            logfileVar = re.match(line).captured("UpdateLogFile");
            break;
        }
    }
    file.close();
    return logfileVar;
}

QString MainWindow::getClamdDatabaseDirectoryName(){
    QRegularExpression re;
    QString ddVar = "";
    QFile file(getValDB("clamdconf"));

    if(!file.exists())
        return QString();

    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();

    while(!file.atEnd()){
        QByteArray line = file.readLine();

        re.setPattern("^DatabaseDirectory\\s+(?<DatabaseDirectory>.+)\\s*$");
        if(re.match(line).hasMatch()){
            ddVar = re.match(line).captured("DatabaseDirectory");
            break;
        }
    }
    file.close();
    return ddVar;
}

QString MainWindow::getValDB(QString key){
    QSqlQuery query;
    query.prepare("SELECT val FROM basics WHERE key = ? ;");
    query.addBindValue(key);
    if(!query.exec())
        return QString();
    if(!query.first())
        return QString();
    return query.value(0).toString();
}

void MainWindow::setValDB(QString key, QString val){
    QSqlQuery query;
    query.prepare("INSERT OR REPLACE INTO basics ( key , val ) VALUES ( :key1 , :val1 );");
    query.bindValue(":key1", key);
    query.bindValue(":val1", val);
    query.exec();
}

bool MainWindow::setUID(){
    if(!getuid()){ //only setuid/setgid if root
        struct passwd *user = NULL;
        QRegularExpression userRegex("^User\\s+(.*)$");
        QFile clamdconf(getValDB("clamdconf"));
        if (clamdconf.open(QIODevice::ReadOnly)){
            QTextStream clamdconfStream(&clamdconf);
            while (!clamdconfStream.atEnd()){
                QString line = clamdconfStream.readLine();
                if(userRegex.match(line).hasMatch()){
                    QString setuidUsername = "";
                    setuidUsername = line.replace(userRegex,"\\1");
                    if((user = getpwnam(qPrintable(setuidUsername))) == NULL){
                        fprintf(stderr, "ERROR: Can't get information about user %s.\n", qPrintable(setuidUsername));
                        return false;
                    }
                    if(setgid(user->pw_gid)){
                        fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int)user->pw_gid);
                        return false;
                    }else{
                        fprintf(stderr, "setgid(%d) sucessful.\n", (int)user->pw_gid);
                    }
                    if(setuid(user->pw_uid)){
                        fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int)user->pw_uid);
                        return false;
                    }else{
                        fprintf(stderr, "setuid(%d) sucessful.\n", (int)user->pw_uid);
                    }
                    break;
                }
            }
            clamdconf.close();
        }
    }
    return true;
}

bool MainWindow::requestUpdatedcDns(){
    if(time(NULL) < (cDns.last_lookup_timestamp + 600))
        return true;
    cDns.isReset = true;
    cDns.ver_major = 0;
    cDns.ver_minor = 0;
    cDns.ver_build = 0;
    cDns.ver_compiled = 0;
    cDns.main_ver = 0;
    cDns.daily_ver = 0;
    cDns.timestamp = 0;
    cDns.flevel = 0;
    cDns.bytecode_ver = 0;
    cDns.last_lookup_timestamp = 0;

    QDnsLookup *dns = new QDnsLookup(this);
    QEventLoop requestLoop;
    QTimer requestTimer;

    requestTimer.setSingleShot(true);

    connect(&requestTimer, &QTimer::timeout, &requestLoop, &QEventLoop::quit);
    connect(dns, &QDnsLookup::finished,  &requestLoop, &QEventLoop::quit);

    requestTimer.start(5000);

    dns->setType(QDnsLookup::TXT);
    dns->setName("current.cvd.clamav.net");
    dns->lookup();

    requestLoop.exec();

    if (dns->error() != QDnsLookup::NoError) {
        dns->deleteLater();
        QString res = getValDB("lastlookuptimestamp");
        if(res.isEmpty())
            return false;
        bool ok;
        int num = res.toInt(&ok, 10);
        if(!ok)
            return false;
        if(time(NULL) < (num + 7*24*3600) && num < time(NULL)){
            res = getValDB("dailyver");
            int num1 = res.toInt(&ok, 10);
            if(!ok)
                return false;

            res = getValDB("mainver");
            int num2 = res.toInt(&ok, 10);
            if(!ok)
                return false;

            res = getValDB("bytecodever");
            int num3 = res.toInt(&ok, 10);
            if(!ok)
                return false;

            cDns.daily_ver = num1;
            cDns.main_ver = num2;
            cDns.bytecode_ver = num3;
            return true;
        }else{
            return false;
        }
    }else{
        const auto records = dns->textRecords();
        for (const QDnsTextRecord &record : records) {
            QByteArray bytes;
            foreach (const QByteArray &item, record.values())
                bytes += QString::fromLocal8Bit(item);
            QStringList tmp = QString(bytes).split(":");
            if(tmp.length() == 8){
                cDns.ver_major = tmp.at(0).split(".").at(0).toInt();
                cDns.ver_minor = tmp.at(0).split(".").at(1).toInt();
                cDns.ver_build = tmp.at(0).split(".").at(2).toInt();
                cDns.ver_compiled =
                        QT_VERSION_CHECK(cDns.ver_major, cDns.ver_minor, cDns.ver_build);
                cDns.main_ver = tmp.at(1).toInt();
                cDns.daily_ver = tmp.at(2).toInt();
                cDns.timestamp = tmp.at(3).toInt();
                cDns.flevel = tmp.at(5).toInt();
                cDns.bytecode_ver = tmp.at(7).toInt();
                cDns.last_lookup_timestamp = time(NULL);
                setValDB("lastlookuptimestamp", QString::number(cDns.last_lookup_timestamp));
                setValDB("dailyver", QString::number(cDns.daily_ver));
                setValDB("mainver", QString::number(cDns.main_ver));
                setValDB("bytecodever", QString::number(cDns.bytecode_ver));
                cDns.isReset = false;
            }
            break;
        }
        dns->deleteLater();
    }
    return true;
}

bool MainWindow::checkDefsHeaderDaily(){
    dailyDefHeader.db_name = "";
    dailyDefHeader.timestamp_str = "";
    dailyDefHeader.version = 0;
    dailyDefHeader.num_unknown = 0;
    dailyDefHeader.flevel = 0;
    dailyDefHeader.user_name = "";
    dailyDefHeader.timestamp = 0;
    QString ddname = getClamdDatabaseDirectoryName();

    QFile file(ddname+"/daily.cld");
    if(!file.exists()){
        file.setFileName(ddname+"/daily.cvd");
        if(!file.exists()){
            errorMsg(ddname+tr("/daily.{cld|cvd} doesnt exist"));
            return false;
        }
    }

    if(!file.open(QIODevice::ReadOnly)){
        errorMsg(ddname+tr("/daily.{cld|cvd} file not open read-only"));
        return false;
    }

    QByteArray bytes = file.read(0x200);
    file.close();
    if(bytes.length() != 0x200){
        errorMsg(ddname+tr("/daily.{cld|cvd} smaller than 0x200 bytes"));
        return false;
    }
    QStringList header = QString(bytes).trimmed().split(":");
    if(header.length() != 9){
        errorMsg(ddname+tr("/daily.{cld|cvd} header not parsed correctly"));
        return false;
    }
    dailyDefHeader.db_name = header.at(0);
    dailyDefHeader.timestamp_str = header.at(1);
    dailyDefHeader.version = header.at(2).toInt();
    dailyDefHeader.num_unknown = header.at(3).toInt();
    dailyDefHeader.flevel = header.at(4).toInt();
    dailyDefHeader.user_name = header.at(7);
    dailyDefHeader.timestamp = header.at(8).toInt();
    return true;
}

bool MainWindow::checkDefsHeaderMain(){
    mainDefHeader.db_name = "";
    mainDefHeader.timestamp_str = "";
    mainDefHeader.version = 0;
    mainDefHeader.num_unknown = 0;
    mainDefHeader.flevel = 0;
    mainDefHeader.user_name = "";
    mainDefHeader.timestamp = 0;
    QString ddname = getClamdDatabaseDirectoryName();

    QFile file(ddname+"/main.cld");
    if(!file.exists()){
        file.setFileName(ddname+"/main.cvd");
        if(!file.exists()){
            errorMsg(ddname+tr("/main.{cld|cvd} doesnt exist"));
            return false;
        }
    }
    if(!file.open(QIODevice::ReadOnly)){
        errorMsg(ddname+tr("/main.{cld|cvd} file not open read-only"));
        return false;
    }
    QByteArray bytes = file.read(0x200);
    file.close();
    if(bytes.length() != 0x200){
        errorMsg(ddname+tr("/main.{cld|cvd} smaller than 0x200 bytes"));
        return false;
    }
    QStringList header = QString(bytes).trimmed().split(":");
    if(header.length() != 9){
        errorMsg(ddname+tr("/main.{cld|cvd} header not parsed correctly"));
        return false;
    }
    mainDefHeader.db_name = header.at(0);
    mainDefHeader.timestamp_str = header.at(1);
    mainDefHeader.version = header.at(2).toInt();
    mainDefHeader.num_unknown = header.at(3).toInt();
    mainDefHeader.flevel = header.at(4).toInt();
    mainDefHeader.user_name = header.at(7);
    mainDefHeader.timestamp = header.at(8).toInt();
    return true;
}

bool MainWindow::checkDefsHeaderByte(){
    byteDefHeader.db_name = "";
    byteDefHeader.timestamp_str = "";
    byteDefHeader.version = 0;
    byteDefHeader.num_unknown = 0;
    byteDefHeader.flevel = 0;
    byteDefHeader.user_name = "";
    byteDefHeader.timestamp = 0;
    QString ddname = getClamdDatabaseDirectoryName();

    QFile file(ddname+"/bytecode.cld");
    if(!file.exists()){
        file.setFileName(ddname+"/bytecode.cvd");
        if(!file.exists()){
            errorMsg(ddname+tr("/bytecode.{cld|cvd} doesnt exist"));
            return false;
        }
    }
    if(!file.open(QIODevice::ReadOnly)){
        errorMsg(ddname+tr("/bytecode.{cld|cvd} file not open read-only"));
        return false;
    }
    QByteArray bytes = file.read(0x200);
    file.close();
    if(bytes.length() != 0x200){
        errorMsg(ddname+tr("/bytecode.{cld|cvd} smaller than 0x200 bytes"));
        return false;
    }
    QStringList header = QString(bytes).trimmed().split(":");
    if(header.length() != 9){
        errorMsg(ddname+tr("/bytecode.{cld|cvd} header not parsed correctly"));
        return false;
    }
    byteDefHeader.db_name = header.at(0);
    byteDefHeader.timestamp_str = header.at(1);
    byteDefHeader.version = header.at(2).toInt();
    byteDefHeader.num_unknown = header.at(3).toInt();
    byteDefHeader.flevel = header.at(4).toInt();
    byteDefHeader.user_name = header.at(7);
    byteDefHeader.timestamp = header.at(8).toInt();
    return true;
}

void MainWindow::timerSlot(){
    bool isClamdError = false, isFreshclamError = false, isClamonaccError = false, isUpdateError = false, isActiveThreatDetected = false;
    int rClamd = -1, rFresh = -1, rClamonacc = -1;
    ckProc(&rClamd, &rFresh, &rClamonacc);

    //CLAMD NOT RUNNING
    if(rClamd < 1){
        statusSetError();
        setErrorAVReason(tr("clamd is currently not running."));
        isClamdError = true;
    }

    //CLAMD SOCKET NOT RUNNING
    if(!isClamdError && localSocketFilename.isEmpty()){
        localSocketFilename = getClamdLocalSocketname();
    }
    if(!isClamdError && localSocketFilename.isEmpty()){
        statusSetError();
        setErrorAVReason(tr("clamd must be configured to run locally on a \"local socket\", which is currently not enabled."));
        isClamdError = true;
    }

    //PING/PONG FAILED
    if(!isClamdError){
        localSocket->abort();
        localSocket->setServerName(localSocketFilename);
        localSocket->connectToServer(QLocalSocket::ReadWrite);
        if(!localSocket->waitForConnected() ||
            localSocket->write(QByteArray("PING", 4)) != (qint64)4 ||
            !localSocket->waitForReadyRead(250) ||
            localSocket->readAll() != QByteArray("PONG\n", 5)){
            statusSetError();
            setErrorAVReason(tr("clamd failed to ping back."));
            isClamdError = true;
        }
    }

    //CLAMD OK
    if(!isClamdError)
        ui->labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/check_16.png"));

    //FRESHCLAM NOT RUNNING
    if(rFresh < 1){
        ui->labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        isFreshclamError = true;
        if(!isClamdError){
            statusSetError();
            ui->labelStatusProtectionStateDetails->setText(tr("freshclam is currently not running."));
        }
    }else{
        ui->labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }

    //ONACCESS NOT RUNNING
    if(getValDB("monitoronaccess")==tr("yes") && rClamonacc < 1){
        ui->labelStatusEnabledItem3->setText(tr("OnAccess"));
        ui->labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        isClamonaccError = true;
        if(!isClamdError && !isFreshclamError){
            statusSetError();
            ui->labelStatusProtectionStateDetails->setText(tr("OnAccess is configured, but currently not running."));
        }
    }else if(getValDB("monitoronaccess")==tr("yes")){
        ui->labelStatusEnabledItem3->setText(tr("OnAccess"));
        ui->labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }else{
        ui->labelStatusEnabledItem3->setText(tr("OnAccess - Disabled in Configure"));
        ui->labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/ques_16.png"));
    }

    //CLAMAV DEFS OUTDATED
    if(!checkDefsHeaderDaily()){
        ui->labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        ui->labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        ui->labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the daily.cld virus defnition database. The file's header looks malformed."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError){
             statusSetWarn();
             ui->labelStatusProtectionStateDetails->setText(tr("Unable To Check daily.cld"));
        }
    }
    if(!isUpdateError && !checkDefsHeaderMain()){
        ui->labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        ui->labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        ui->labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the main.cld virus defnition database. The file's header looks malformed."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError){
             statusSetWarn();
             ui->labelStatusProtectionStateDetails->setText(tr("Unable To Check main.cld"));
        }
    }
    if(!isUpdateError && !checkDefsHeaderByte()){
        ui->labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        ui->labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        ui->labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the bytecode.cld virus defnition database. The file's header looks malformed."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError){
             statusSetWarn();
             ui->labelStatusProtectionStateDetails->setText(tr("Unable To Check bytecode.cld"));
        }
    }
    if(!isUpdateError && !requestUpdatedcDns()){
        ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/ques_16.png"));
        ui->labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        ui->labelUpdateMessageDetails->setText(tr("There was a problem attempting to lookup the DNS TXT current virus defnition info. Check your internet connectivity."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError){
             statusSetWarn();
             ui->labelStatusProtectionStateDetails->setText(tr("Unable To Establish Internet Connection"));
        }
    }
    if(!isUpdateError &&
            ( cDns.daily_ver != dailyDefHeader.version ||
              cDns.main_ver != mainDefHeader.version ||
              cDns.bytecode_ver != byteDefHeader.version
            )
        ){
        ui->labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        ui->labelUpdateMessage->setText(tr("Virus Definitions Update Failed."));
        ui->labelUpdateMessageDetails->setText(tr("There was a problem attempting to update the virus definition database to the most current form. The virus definition database is out-of-date"));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError){
            statusSetWarn();
            ui->labelStatusProtectionStateDetails->setText(tr("Virus Definitions Are Out Of Date"));
        }
    }else if(!isUpdateError){
        ui->labelStatusEnabledItem4->setText(tr("Definitions Up To Date"));
        ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/check_16.png"));
        ui->labelUpdateMessage->setText(tr("Virus Definitions Updated."));
        ui->labelUpdateMessageDetails->setText(tr("The virus definition database is up-to-date<br /><br />"));
    }

    ui->labelUpdateLocalDailyVal->setText(QDateTime::fromMSecsSinceEpoch(((quint64)dailyDefHeader.timestamp)*1000).toString("MM/dd/yyyy hh:mm:ss AP")
                                          +tr(" d-")+QString::number(dailyDefHeader.version));
    ui->labelUpdateLocalMainVal->setText(QDateTime::fromMSecsSinceEpoch(((quint64)mainDefHeader.timestamp)*1000).toString("MM/dd/yyyy hh:mm:ss AP")
                                         +tr(" m-")+QString::number(mainDefHeader.version));
    ui->labelUpdateLocalByteVal->setText(QDateTime::fromMSecsSinceEpoch(((quint64)byteDefHeader.timestamp)*1000).toString("MM/dd/yyyy hh:mm:ss AP")
                                         +tr(" b-")+QString::number(byteDefHeader.version));

    ui->labelUpdateRemoteVersionVal->setText(
                tr("d-")+QString::number(cDns.daily_ver)+
                tr(", m-")+QString::number(cDns.main_ver)+
                tr(", b-")+QString::number(cDns.bytecode_ver));

    //Update Logfile Display
    ckLogfileDisplay();

    //Check Active Threats
    QStringList existsOnFs = ckExistsOnFs();
    if(existsOnFs.length() != 0){
        isActiveThreatDetected = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isUpdateError){
            statusSetError();
            ui->labelStatusProtectionStateDetails->setText(tr("Active threat detected on filesystem."));
        }
        foreach(QString filename, existsOnFs){
            if(!QFileInfo(filename).exists()){
                QSqlQuery query;
                query.prepare("UPDATE OR IGNORE found SET existsonfs = 0 WHERE filename = :filename ;");
                query.bindValue(":filename", filename);
                query.exec();
            }
        }
        if(refreshFoundTableOnUpdate){
            initializeEventsFoundTableWidget(0);
            refreshFoundTableOnUpdate = false;
        }
    }

    //Align schedule timer
    if(!timerSchedule->isActive()){
        int seconds = QDateTime::currentDateTime().time().second();
        if(seconds > 0 && seconds < 4){ //1-3
            timerSchedule->start(60000);
            ckScheduledScans();
        }
    }

    if(isClamdError || isFreshclamError || isClamonaccError || isUpdateError || isActiveThreatDetected)
        return;

    //NOMINAL
    statusSetOk();
}

void MainWindow::ckLogfileDisplay(){
    QString logfileVar = getClamdLogFileName();
    if(logfileVar.isEmpty())
        return;
    qint64 ts = (QFileInfo(logfileVar).lastModified().toMSecsSinceEpoch()/1000);
    if(lastTimestampClamdLogFile != ts){
        lastTimestampClamdLogFile = ts;
        addExistingEventsParseClamlog(logfileVar, false, true);
        initializeEventsGeneralTableWidget(intEventGeneralPageNumber);
        initializeEventsFoundTableWidget(intEventFoundPageNumber);
    }
}

void MainWindow::ckScheduledScans(){
    QDateTime timestamp = QDateTime::currentDateTime();
    for(int i = 0; i < ui->listWidgetSchedule->count(); i++){
        bool ok1, ok2, ok3;
        int num1, num2, num3;
        QListWidgetItem *item = ui->listWidgetSchedule->item(i);
        QWidget *widget = ui->listWidgetSchedule->itemWidget(item);
        QLayout *layout = widget->layout();

        //QLabel *labelDelete = static_cast<QLabel *>(layout->itemAt(0)->widget());
        QCheckBox *checkBoxEnable = static_cast<QCheckBox *>(layout->itemAt(1)->widget());
        if(!checkBoxEnable->isCheckable() || !checkBoxEnable->isChecked())
            continue;
        //QLineEdit *lineEditName = static_cast<QLineEdit *>(layout->itemAt(2)->widget());
        QLineEdit *lineEditMinute = static_cast<QLineEdit *>(layout->itemAt(3)->widget());
        QLineEdit *lineEditHour = static_cast<QLineEdit *>(layout->itemAt(4)->widget());
        QLineEdit *lineEditDayMonth = static_cast<QLineEdit *>(layout->itemAt(5)->widget());
        QLineEdit *lineEditMonth = static_cast<QLineEdit *>(layout->itemAt(6)->widget());
        QLineEdit *lineEditDayWeek = static_cast<QLineEdit *>(layout->itemAt(7)->widget());
        //QPushButton *addFileWidget = static_cast<QPushButton *>(layout->itemAt(8)->widget());
        //QPushButton *addDirWidget = static_cast<QPushButton *>(layout->itemAt(9)->widget());
        QStringListWidget *stringlistWidget = static_cast<QStringListWidget *>(layout->itemAt(10)->widget());

        parseScheduleMinutes(lineEditMinute->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(!ckScheduledScanMatch(timestamp.time().minute(), ok1, num1, ok2, num2, ok3, num3))
            continue;
        parseScheduleHours(lineEditHour->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(!ckScheduledScanMatch(timestamp.time().hour(), ok1, num1, ok2, num2, ok3, num3))
            continue;
        parseScheduleDayMonth(lineEditDayMonth->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(!ckScheduledScanMatch(timestamp.date().daysInMonth(), ok1, num1, ok2, num2, ok3, num3))
            continue;
        parseScheduleMonth(lineEditMonth->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(!ckScheduledScanMatch(timestamp.date().month(), ok1, num1, ok2, num2, ok3, num3))
            continue;
        parseScheduleDayWeek(lineEditDayWeek->text(), &ok1, &num1, &ok2, &num2, &ok3, &num3);
        if(!ckScheduledScanMatch(timestamp.date().dayOfWeek(), ok1, num1, ok2, num2, ok3, num3))
            continue;
        if(stringlistWidget->getQStringList().isEmpty())
            continue;
        if(!isScanActive){
            allShow();
            scanDialog->show();
            initializeFreelanceScan(isScanActive, stringlistWidget->getQStringList());
        }
    }
}

bool MainWindow::ckScheduledScanMatch(const int time_val, const bool ok1, const int num1, const bool ok2, const int num2, const bool ok3, const int num3){
    if(!ok1)
        return false;
    if(ok3 && ok2){
        if(num1 == -1 || time_val < num1 ||
                ((time_val-num1)%num3)!=0 ||
                time_val > num2)
            return false;
    }else if(ok3 && !ok2){
        if(num1 == -1){
            if((time_val%num3)!=0)
                return false;
        }else{
            if(time_val < num1 ||
                    ((time_val-num1)%num3)!=0)
                return false;
        }
    }else if(!ok3 && ok2){
        if(num1 == -1 || time_val < num1 ||
                time_val > num2)
            return false;
    }else{
        if(num1 != -1){
            if(time_val != num1)
                return false;
        }
    }
    return true;
}

QStringList MainWindow::ckExistsOnFs(){
    QStringList ret = QStringList();
    qint64 num = -1;
    QSqlQuery query;
    query.prepare("SELECT COUNT(*) FROM found WHERE existsonfs = 1;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > 0){
            query.prepare("SELECT filename FROM found WHERE existsonfs = 1;");
            query.exec();
            while(query.next())
                ret << query.value(0).toString();
        }
    }
    return ret;
}

void MainWindow::ckProc(int *pidClamd, int *pidFreshclam, int *pidClamonacc){
    (*pidClamd) = -1;
    (*pidFreshclam) = -1;
    (*pidClamonacc) = -1;

    int count = 0;
    static proc_t proc;
    PROCTAB* pproctab;
    pproctab = (*openproc_p)(PROC_FILLCOM, NULL);
    while((*readproc_p)(pproctab, &proc) != NULL){
        if(&(proc.cmdline[0]) != NULL && QFileInfo(QString(proc.cmdline[0])).baseName() == QString("clamd")){
            if(pidClamd != Q_NULLPTR)
                (*pidClamd) = proc.tid;
            count++;
        }else if(&(proc.cmdline[0]) != NULL && QFileInfo(QString(proc.cmdline[0])).baseName() == QString("freshclam")){
            if(pidFreshclam != Q_NULLPTR)
                (*pidFreshclam) = proc.tid;
            count++;
        }else if(&(proc.cmdline[0]) != NULL && QFileInfo(QString(proc.cmdline[0])).baseName() == QString("clamonacc")){
            if(pidClamonacc != Q_NULLPTR)
                (*pidClamonacc) = proc.tid;
            count++;
        }
        if(count >=3)
            break;
    }
    (*closeproc_p)(pproctab);
}

quint32 MainWindow::clamdscanVersion(QByteArray *clamdscan_ver){
    QProcess whichClamdscanProc;
    whichClamdscanProc.start("which", QStringList({"clamdscan"}));
    whichClamdscanProc.waitForFinished();
    QByteArray whichClamdscanRet = whichClamdscanProc.readAllStandardOutput();
    whichClamdscanRet = ((whichClamdscanRet.mid(whichClamdscanRet.length()-1, 1) == QByteArray("\n",1))?whichClamdscanRet.mid(0, whichClamdscanRet.length()-1):whichClamdscanRet);
    whichClamdscanProc.close();
    if(whichClamdscanRet.isEmpty())
        return 0xFFFFFFFF;
    QProcess clamdscanProc;
    clamdscanProc.start("clamdscan", QStringList({"--version"}));
    clamdscanProc.waitForFinished();
    QByteArray clamdscanRet = clamdscanProc.readAllStandardOutput();
    clamdscanRet = clamdscanRet.mid(7, clamdscanRet.indexOf('/')-7);
    (*clamdscan_ver) = clamdscanRet;
    QByteArray major = clamdscanRet.mid(0,clamdscanRet.indexOf('.'));
    clamdscanRet = clamdscanRet.mid(clamdscanRet.indexOf('.')+1);
    QByteArray minor = clamdscanRet.mid(0,clamdscanRet.indexOf('.'));
    clamdscanRet = clamdscanRet.mid(clamdscanRet.indexOf('.')+1);
    QByteArray build = clamdscanRet.mid(0,clamdscanRet.indexOf('.'));
    int major_i, minor_i, build_i;
    bool ok;
    major_i = QString(major).toInt(&ok, 10);
    if(!ok)
        return 0xFFFFFFFF;
    minor_i = QString(minor).toInt(&ok, 10);
    if(!ok)
        return 0xFFFFFFFF;
    build_i = QString(build).toInt(&ok, 10);
    if(!ok)
        return 0xFFFFFFFF;

    return QT_VERSION_CHECK(major_i, minor_i, build_i);
}
#ifdef CLAMONE_COUNT_ITEMS_SCANNED
void MainWindow::countTotalScanItems(const QStringList items, quint64 *count){
    if(count == Q_NULLPTR)
        return;
    foreach(QString item, items)
        countScanItem(item, count);
}

void MainWindow::countScanItem(const QString item, quint64 *count){
    QFileInfo qfi(item);
    if(count == Q_NULLPTR || item == tr(".") || item == tr(".."))
        return;
    if(!qfi.exists())
        return;
    if(qfi.isDir()){
        QStringList qsl;
        QFileInfoList qfil = QDir(qfi.absoluteFilePath()).entryInfoList();
        foreach(QFileInfo fileinfo, qfil){
            if(fileinfo.fileName() == tr(".") || fileinfo.fileName() == tr(".."))
                continue;
            qsl.append(fileinfo.absoluteFilePath());
        }
        countTotalScanItems(qsl, count);
    }else if(qfi.isFile()){
        (*count)++;
    }else if(qfi.isSymLink()){
        countScanItem(qfi.canonicalFilePath(), count);
    }
}
#endif //CLAMONE_COUNT_ITEMS_SCANNED

quint8 MainWindow::getQuarantineFileStatus(QString quarantine_name){
    quint8 ret = 0;
    QSqlQuery query;
    query.prepare("SELECT verified FROM quarantine WHERE quarantine_name = :quarantine_name1 ;");
    query.bindValue(":quarantine_name1", quarantine_name);
    query.exec();
    if(query.next())
        ret = query.value(0).toInt();
    return ret;
}

bool MainWindow::getQuarantineInfo(QString quarantine_name, quint32 *timestamp, quint64 *file_size, QByteArray *file_name){
    bool ret = false;
    (*timestamp) = 0;
    (*file_name) = QByteArray();
    (*file_size) = 0;
    QSqlQuery query;
    query.prepare("SELECT timestamp, file_name, file_size FROM quarantine WHERE quarantine_name = :quarantine_name1 ;");
    query.bindValue(":quarantine_name1", quarantine_name);
    query.exec();
    if(query.next()){
        (*timestamp) = query.value(0).toInt();
        (*file_name) = query.value(1).toString().toLocal8Bit();
        (*file_size) = query.value(2).toInt();
        ret = true;
    }
    return ret;
}

void MainWindow::setErrorAVReason(QString in){
    ui->labelStatusProtectionStateDetails->setText(in);
    ui->labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/cross_16.png"));
    ui->labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/ques_16.png"));
    ui->labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/ques_16.png"));
    ui->labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/ques_16.png"));
}

void MainWindow::statusSetError(){
    QIcon icon = QIcon(":/images/main_icon_red.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    ui->listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_red.png"));

    ui->frameStatus->setStyleSheet("background-color: #fbc2c1;");

    ui->labelTL->setStyleSheet("background-color: #ec1a1a;");
    ui->labelTM->setStyleSheet("background-color: #ec1a1a;");
    ui->labelTR->setStyleSheet("background-color: #ec1a1a;");

    ui->labelStatusProtectionState->setText(tr("Error"));
    ui->labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::statusSetWarn(){
    QIcon icon = QIcon(":/images/main_icon_yellow.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    ui->listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_yellow.png"));

    ui->frameStatus->setStyleSheet("background-color: #fef2d1;");

    ui->labelTL->setStyleSheet("background-color: #eaec1a;");
    ui->labelTM->setStyleSheet("background-color: #eaec1a;");
    ui->labelTR->setStyleSheet("background-color: #eaec1a;");

    ui->labelStatusProtectionState->setText(tr("Warning"));
    ui->labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::statusSetOk(){
    QIcon icon = QIcon(":/images/main_icon_green.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    ui->listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_green.png"));

    ui->frameStatus->setStyleSheet("background-color: #cbfbd1;");

    ui->labelTL->setStyleSheet("background-color: #12bf12;");
    ui->labelTM->setStyleSheet("background-color: #12bf12;");
    ui->labelTR->setStyleSheet("background-color: #12bf12;");

    ui->labelStatusProtectionState->setText(tr("All Systems Nominal"));
    ui->labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::statusSetGrey(){
    QIcon icon = QIcon(":/images/main_icon_grey.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    ui->listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_grey.png"));

    ui->frameStatus->setStyleSheet("background-color: #b6b6b6;");

    ui->labelTL->setStyleSheet("background-color: #999999;");
    ui->labelTM->setStyleSheet("background-color: #999999;");
    ui->labelTR->setStyleSheet("background-color: #999999;");

    ui->labelStatusProtectionState->setText(tr("System Unkonwn"));
    ui->labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::updateSetError(){
    ui->frameUpdate->setStyleSheet("background-color: #fbc2c2;");
}

void MainWindow::updateSetWarn(){
    ui->frameUpdate->setStyleSheet("background-color: #fef2d0;");
}

void MainWindow::updateSetOk(){
    ui->frameUpdate->setStyleSheet("background-color: #cbfbd4;");
}

void MainWindow::updateSetGrey(){
    ui->frameUpdate->setStyleSheet("background-color: #b6b6b6;");
}

void MainWindow::actionExit(){
    QMessageBox msgBox;
    msgBox.setWindowTitle(windowTitle());
    msgBox.setText(tr("<h1><b>Exiting...</b></h1>"));
    msgBox.setInformativeText(tr("Do you want to shutdown ClamOne?"));
    QPushButton *yes = new QPushButton(tr("Yes"));
    msgBox.addButton(yes, QMessageBox::AcceptRole);
    QPushButton *no = new QPushButton(tr("No"));
    msgBox.addButton(no, QMessageBox::RejectRole);
    msgBox.setDefaultButton(QMessageBox::No);
    msgBox.setIcon(QMessageBox::Question);
    int ret = msgBox.exec();
    switch (ret) {
      case QMessageBox::AcceptRole:
      case QMessageBox::Yes:
          markClamOneStopped();
          exitProgram();
          break;
      default:
        break;
    }
}

void MainWindow::aboutToQuit(){
    qDebug() << "Reached 'About To Quit'";
    procKill();
    threadKill();
}

void MainWindow::procKill(){
    if(p && p->state() != QProcess::NotRunning){
        p->terminate();
        p->waitForFinished(3000);
    }
    if(p && p->state() != QProcess::NotRunning){
        p->kill();

    }
    isScanActive = false;
}

void MainWindow::threadKill(){
    for(int i = 0; i < qMax(QThread::idealThreadCount(),1); i++)
        threads_list.at(i)->quit();
}

void MainWindow::closeEvent(QCloseEvent *event){
    allHide();
    markClamOneStopped();
#ifndef CLAMONE_DEBUG
    event->ignore();
#else
    event->accept();
#endif
}


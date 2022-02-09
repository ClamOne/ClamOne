#include "MainWindow.h"

QT_CHARTS_USE_NAMESPACE

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    InitializeMainWindow();

    //snort --version 2>&1 | grep '~' | sed 's/^.*\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\).*$/\1/'

#if QT_VERSION < QT_VERSION_CHECK(5,10,0)
    qsrand(time(NULL));
#endif
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

    tableWidgetEventGeneral->setColumnWidth(0, 160);

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
    config = new ConfigureDialog(dbFileLocation, this);
    scanDialog = new ScanDialog();
    listerQuarantine = new ListerQuarantine();
    setEnabledQuarantine(getValDB("enablequarantine")=="yes");
    setEnabledSnort(getValDB("enablesnort")=="yes");
    setEnabledOnAccess(getValDB("monitoronaccess")=="yes");

    localSocket = new QLocalSocket(this);
    localSocketFilename = getClamdLocalSocketname();
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::timerSlot);
    timer->start(1000);
    timerSchedule = new QTimer(this);
    connect(timerSchedule, &QTimer::timeout, this, &MainWindow::ckScheduledScans);
    onNextCycle = false;
    quarantineDirectoryWatcher = new QFileSystemWatcher();
    manager = new QNetworkAccessManager();
    refreshQuarantineDirectory();
    updateQuarantineDirectoryUi("");

    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::iconActivated);
    connect(listWidget, &QListWidget::currentRowChanged, stackedWidget, &QStackedWidget::setCurrentIndex);
    connect(stackedWidget, &QStackedWidget::currentChanged, this, &MainWindow::stackedWidgetChanged);
    connect(comboBoxLog, QOverload<int>::of(&QComboBox::activated), stackedWidgetEvents, &QStackedWidget::setCurrentIndex);
    connect(config, &ConfigureDialog::setValDB, this, &MainWindow::setValDB);
    connect(config, &ConfigureDialog::refreshEventGeneral, this, &MainWindow::initializeEventsGeneralTableWidget);
    connect(config, &ConfigureDialog::refreshEventFound, this, &MainWindow::initializeEventsFoundTableWidget);
    connect(config, &ConfigureDialog::refreshEventQuarantined, this, &MainWindow::initializeEventsQuarantinedTableWidget);
    connect(config, &ConfigureDialog::refreshMessages, this, &MainWindow::initializeMessagesTableWidget);
    connect(config, &ConfigureDialog::refreshQuarantineDirectory, this, &MainWindow::refreshQuarantineDirectory);
    connect(config, &ConfigureDialog::setEnabledQuarantine, this, &MainWindow::setEnabledQuarantine);
    connect(config, &ConfigureDialog::setEnabledSnort, this, &MainWindow::setEnabledSnort);
    connect(config, &ConfigureDialog::setEnabledMonitorOnAccess, this, &MainWindow::setEnabledOnAccess);
    connect(config, &ConfigureDialog::refreshOinkcodeContent, this, &MainWindow::refreshOinkcode);
    connect(this, &MainWindow::addExclusionClamdconf, config, &ConfigureDialog::addExclusionClamdconf);
    connect(scanDialog, &ScanDialog::parseClamdscanLine, this, &MainWindow::parseClamdscanLine);
    connect(scanDialog, &ScanDialog::initScanProcess, this, &MainWindow::initScanProcess);
    connect(scanDialog, &ScanDialog::setScanActive, this, &MainWindow::setScanActive);
    connect(this, &MainWindow::detectedThreatFound, this, &MainWindow::detectedThreatListener);
    connect(quarantineDirectoryWatcher, &QFileSystemWatcher::directoryChanged, this, &MainWindow::updateQuarantineDirectoryUi);
    connect(listerQuarantine, &ListerQuarantine::yesClicked, this, &MainWindow::ListerQuarantineYesClicked);
    connect(listerQuarantine, &ListerQuarantine::noClicked, this, &MainWindow::ListerQuarantineNoClicked);
    connect(this, &MainWindow::initializeFreelanceScan, scanDialog, &ScanDialog::initializeFreelanceScan);
    connect(comboBoxGraphsSubTitleSelector, QOverload<int>::of(&QComboBox::activated), [=](int indexComboBox){
        QList<quint8> mapper;
        if(getValDB("enablequarantine") == "yes" && getValDB("enablesnort") == "yes"){
            mapper = QList<quint8>({0,1,2,3});
        }else if(getValDB("enablequarantine") == "yes" && getValDB("enablesnort") != "yes"){
            mapper = QList<quint8>({0,1,2});
        }else if(getValDB("enablequarantine") != "yes" && getValDB("enablesnort") == "yes"){
            mapper = QList<quint8>({0,1,3});
        }else{
            mapper = QList<quint8>({0,1});
        }
        stackedWidgetGraphs->setCurrentIndex(mapper.at(indexComboBox));
    });

    dnsSuccess = false;
    cDns.last_lookup_timestamp = 0;
    snort_local_version_last_lookup_timestamp = 0;
    snort_local_rules_last_lookup_timestamp = 0;

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

    for(int i = 0; i < qMax(QThread::idealThreadCount(),1); i++)
        threads_list.append(new QThread(this));

    QTimer::singleShot(100, [=]() {
        initializeDateTimeLineGraphWidget(1);
        initializeDateTimeLineGraphWidget(2);
        initializeDateTimeLineGraphWidget(3);
        initializeDateTimeLineGraphWidget(4);
    });

    snortGetLocalVersion();
    snortGetLocalTimeModifiy();
    snortGetRemoteVersions();
    snortGetRemoteTimeModifiy();
}


MainWindow::~MainWindow(){

}

void MainWindow::allHide(){
    setVisible(false);
    about->hide();
    config->hide();
    scanDialog->hide();
}

void MainWindow::scanShow(){
    allShow();
    stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Scan);
    listWidget->setCurrentRow(ClamOneMainStackOrder::Scan);
}

void MainWindow::statusShow(){
    allShow();
    stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Status);
    listWidget->setCurrentRow(ClamOneMainStackOrder::Status);
}

void MainWindow::historyShow(){
    allShow();
    stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Log);
    listWidget->setCurrentRow(ClamOneMainStackOrder::Log);
}

void MainWindow::updateShow(){
    allShow();
    stackedWidget->setCurrentIndex(ClamOneMainStackOrder::Update);
    listWidget->setCurrentRow(ClamOneMainStackOrder::Update);
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
    config->show();
    config->setVersion(ret);
    config->updateClamdconfLoc(getValDB("clamdconf"));
    config->updateFreshclamconfLoc(getValDB("freshclamconf"));
    config->updateMonitorOnAccess(getValDB("monitoronaccess")=="yes");
    config->updateEntriesPerPage(getValDB("entriesperpage"));
    config->updateEnableQuarantine(getValDB("enablequarantine")=="yes");
    config->updateEnableSnort(getValDB("enablesnort")=="yes");
    config->updateMaximumQuarantineFileSize(getValDB("maxquarantinesize").toInt());
    config->updateLocationQuarantineFileDirectory(getValDB("quarantinefilesdirectory"));
    config->updateLocationSnortRules(getValDB("snortconf"));
    config->updateSnortOinkcode(getValDB("oinkcode"));
    config->updateInstallCond();
}

bool MainWindow::find_file(QByteArray *filepath, QString name){
    if(!(*filepath).isEmpty() && QFileInfo(*filepath).exists() && QFileInfo(*filepath).baseName() == name)
        return true;
    QProcess whichClamdProc;
    whichClamdProc.start("which", QStringList({name}));
    whichClamdProc.waitForFinished();
    (*filepath) = whichClamdProc.readAllStandardOutput();
    (*filepath) = (((*filepath).mid((*filepath).length()-1, 1) == QByteArray("\n",1))?(*filepath).mid(0, (*filepath).length()-1):(*filepath));
    whichClamdProc.close();
    if((*filepath).isEmpty()){
        if(QFileInfo("/bin/"+name).exists()){
            (*filepath) = QByteArray("/bin/"+name.toLocal8Bit());
        }
        if((*filepath).isEmpty() && QFileInfo("/sbin/"+name).exists()){
            (*filepath) = QByteArray("/sbin/"+name.toLocal8Bit());
        }
        if((*filepath).isEmpty() && QFileInfo("/usr/bin/"+name).exists()){
            (*filepath) = QByteArray("/usr/bin/"+name.toLocal8Bit());
        }
        if((*filepath).isEmpty() && QFileInfo("/usr/sbin/"+name).exists()){
            (*filepath) = QByteArray("/usr/sbin/"+name.toLocal8Bit());
        }
        if((*filepath).isEmpty()){
            qDebug() << "Error: find_file: can't find file \"" << name << "\"";
            return false;
        }
    }
    return true;
}

quint32 MainWindow::checkCurrentClamavVersionInstalled(){
    bool ok = true;
    localSocket->abort();
    localSocket->setServerName(localSocketFilename);
    localSocket->connectToServer(QLocalSocket::ReadWrite);
    if(localSocket->waitForConnected() &&
        localSocket->write(QByteArray("VERSION", 7)) == (qint64)7 &&
        localSocket->waitForReadyRead(250))
    {
        QByteArray versionCmdResult = localSocket->readAll();
        if(!versionCmdResult.isEmpty()){
            quint32 ret = 0;
            QStringList tmp = QString(versionCmdResult).split("/").at(0).split(" ").at(1).split(".");
            if(tmp.length() == 3){
                for(int i = 0; i < 3; i++){
                    ret += tmp.at(i).toInt(&ok,10) << ((2-i)*8);
                    if(!ok)
                        break;
                }
            }
            if(ok)
                return ret;
        }
    }

    QByteArray whichClamdRet;
    if(!find_file(&whichClamdRet, "clamd"))
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
    ok = true;
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
        setValDB("clamdconf", "/etc/clamav/clamd.conf");
    }

    res = getValDB("freshclamconf");
    if(res.isEmpty()){
        setValDB("freshclamconf", "/etc/clamav/freshclam.conf");
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
        setValDB("enablequarantine", "no");
    }

    res = getValDB("enablesnort");
    if(res.isEmpty()){
        setValDB("enablesnort", "no");
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

    res = getValDB("snortconf");
    if(res.isEmpty()){
        setValDB("snortconf", "");
    }

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
    stackedWidget->currentWidget()->setFocus();
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
                labelEventGeneralPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                labelEventGeneralPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            labelEventGeneralPagePosition->setText(tr("0 - 0 (0 entries total)"));
            return 0;
        }
    }

    query.prepare("SELECT * FROM general ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(tableWidgetEventGeneral->rowCount())
        tableWidgetEventGeneral->removeRow(0);
    tableWidgetEventGeneral->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);

    while(query.next()){
        QTableWidgetItem *item = new QTableWidgetItem(query.value(1).toString());
        if(query.value(1).toString().length() > width)
            width = query.value(1).toString().length();

        tableWidgetEventGeneral->insertRow(tableWidgetEventGeneral->rowCount());
        tableWidgetEventGeneral->setItem(tableWidgetEventGeneral->rowCount()-1,0,
             new QTableWidgetItem(
                 QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP")
             ));
        tableWidgetEventGeneral->setItem(tableWidgetEventGeneral->rowCount()-1,1, item);
    }
    tableWidgetEventGeneral->resizeColumnToContents(1);
    tableWidgetEventGeneral->horizontalScrollBar()->setValue(0);
    tableWidgetEventGeneral->verticalScrollBar()->setValue(0);
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
                labelMessagesPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                labelMessagesPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            labelMessagesPagePosition->setText(tr("0 - 0 (0 entries total)"));
            while(tableWidgetMessages->rowCount())
                tableWidgetMessages->removeRow(0);
            return 0;
        }
    }

    query.prepare("SELECT * FROM messages ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(tableWidgetMessages->rowCount())
        tableWidgetMessages->removeRow(0);
    tableWidgetMessages->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);
    while(query.next()){
        QTableWidgetItem *item = new QTableWidgetItem(query.value(1).toString());
        if(query.value(1).toString().length() > width)
            width = query.value(1).toString().length();
        tableWidgetMessages->insertRow(tableWidgetMessages->rowCount());
        tableWidgetMessages->setItem(tableWidgetMessages->rowCount()-1,0,new QTableWidgetItem(
            QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP")
        ));
        tableWidgetMessages->setItem(tableWidgetMessages->rowCount()-1,1, item);
    }
    tableWidgetMessages->horizontalScrollBar()->setValue(0);
    tableWidgetMessages->verticalScrollBar()->setValue(0);
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
        labelGraphsScanedXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        labelGraphsScanedXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        chartviewScanedFiles->setChart(chart);
        color = QColor::fromRgb(0,0,255);
    }else if(state == 2){
        delta_ts = DELTA_BASE * pow(2., graphs_found_xscale);
        ts_range_2 = QDateTime::currentDateTime().toSecsSinceEpoch()-graphs_found_xshift;
        ts_range_1 =  ts_range_2 - delta_ts;
        labelGraphsFoundXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        labelGraphsFoundXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        chartviewThreatsFound->setChart(chart);
        color = QColor::fromRgb(255,0,0);
    }else if(state == 3){
        delta_ts = DELTA_BASE * pow(2., graphs_quarantine_xscale);
        ts_range_2 = QDateTime::currentDateTime().toSecsSinceEpoch()-graphs_quarantine_xshift;
        ts_range_1 =  ts_range_2 - delta_ts;
        labelGraphsQuarantineXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        labelGraphsQuarantineXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        chartviewQuarantinedFiles->setChart(chart);
        color = QColor::fromRgb(0,255,0);
    }else if(state == 4){
        delta_ts = DELTA_BASE * pow(2., graphs_snortevents_xscale);
        ts_range_2 = QDateTime::currentDateTime().toSecsSinceEpoch()-graphs_snortevents_xshift;
        ts_range_1 =  ts_range_2 - delta_ts;
        labelGraphsSnortEventsXYPosition1->setText(QDateTime::fromSecsSinceEpoch(ts_range_1).toString("MMM dd, yyyy h:MM ap"));
        labelGraphsSnortEventsXYPosition2->setText(QDateTime::fromSecsSinceEpoch(ts_range_2).toString("MMM dd, yyyy h:MM ap"));
        chartviewSnortEvents->setChart(chart);
        color = QColor::fromRgb(128,255,0);
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

    while(tableWidgetQuarantine->rowCount())
        tableWidgetQuarantine->removeRow(0);

    qint64 width = 100;
    QDir dir = QFileInfo(qpath).dir();
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
    tableWidgetQuarantine->horizontalHeaderItem(3)->setTextAlignment(Qt::AlignLeft);
    tableWidgetQuarantine->setSortingEnabled(false);
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

        tableWidgetQuarantine->insertRow(tableWidgetQuarantine->rowCount());

        QTableWidgetItem *item0 = new QTableWidgetItem(QString(filename));
        QTableWidgetItem *item1 = new TimestampTableWidgetItem(timestamp);
        QTableWidgetItem *item2 = new QTableWidgetItem((file_size>(1<<30))?
            QString::number(file_size/(1<<30))+tr("GB"):
                (file_size>(1<<20))?
                QString::number(file_size/(1<<20))+tr("MB"):
                    (file_size>(1<<10))?
                    QString::number(file_size/(1<<10))+tr("KB"):
                        QString::number(file_size));
        QTableWidgetItem *item3 = new QTableWidgetItem(qfi.fileName());
        item0->setFlags(item0->flags() ^ Qt::ItemIsEditable);
        item1->setFlags(item1->flags() ^ Qt::ItemIsEditable);
        item2->setFlags(item2->flags() ^ Qt::ItemIsEditable);
        item3->setFlags(item3->flags() ^ Qt::ItemIsEditable);
        tableWidgetQuarantine->setItem(tableWidgetQuarantine->rowCount()-1,0, item0);
        tableWidgetQuarantine->setItem(tableWidgetQuarantine->rowCount()-1,1, item1);
        tableWidgetQuarantine->setItem(tableWidgetQuarantine->rowCount()-1,2, item2);
        tableWidgetQuarantine->setItem(tableWidgetQuarantine->rowCount()-1,3, item3);
    }
    tableWidgetQuarantine->setSortingEnabled(true);
    tableWidgetQuarantine->sortByColumn(1, Qt::DescendingOrder);
    tableWidgetQuarantine->setSortingEnabled(false);
    tableWidgetQuarantine->resizeColumnToContents(0);
    tableWidgetQuarantine->resizeColumnToContents(1);
    tableWidgetQuarantine->resizeColumnToContents(2);
    tableWidgetQuarantine->resizeColumnToContents(3);
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
            labelNumBlockedAttacksVal->setText("<a href=\"newevents\">"+QString::number(num)+"</a>");
        else
            labelNumBlockedAttacksVal->setText("0");
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
    QTimer::singleShot(250, [=]() { qApp->exit(1); });
    qApp->exit(1);
}

qint64 MainWindow::initializeEventsFoundTableWidget(qint64 page, bool reset_position){
    qint64 num = 0;
    qint64 entriesperpage = getEntriesPerPage();
    int orig_vert = tableWidgetEventFound->verticalScrollBar()->value();
    int orig_hori = tableWidgetEventFound->horizontalScrollBar()->value();

    QSqlQuery query;
    updateNewEventsCount();

    query.prepare("SELECT count(*) FROM found;");
    query.exec();
    if(query.next()){
        num = (qint64)query.value(0).toInt();
        if(num > 0){
            if(entriesperpage*(page+1) > num)
                labelEventFoundPagePosition->setText(QString::number(entriesperpage*page+1)+" - "+QString::number(num)+" ("+QString::number(num)+tr(" entries total)"));
            else
                labelEventFoundPagePosition->setText(QString::number(entriesperpage*page+1)+" - "+QString::number(entriesperpage*(page+1))+" ("+QString::number(num)+tr(" entries total)"));
        }else{
            labelEventFoundPagePosition->setText(tr("0 - 0 (0 entries total)"));
            return 0;
        }
    }

    query.prepare("SELECT * FROM found ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(tableWidgetEventFound->rowCount())
        tableWidgetEventFound->removeRow(0);

    tableWidgetEventFound->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);
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

        int currentRowNum = tableWidgetEventFound->rowCount();
        tableWidgetEventFound->insertRow(currentRowNum);
        tableWidgetEventFound->setItem(currentRowNum, 0, itemTimestamp);
        tableWidgetEventFound->setCellWidget(currentRowNum, 0, labelTimestamp);
        tableWidgetEventFound->setItem(currentRowNum, 1, itemMessage);
        tableWidgetEventFound->setCellWidget(currentRowNum, 1, labelMessage);
        tableWidgetEventFound->setItem(currentRowNum, 2, itemButtons);
        tableWidgetEventFound->setCellWidget(currentRowNum, 2, widgetButtons);

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
    tableWidgetEventFound->resizeColumnToContents(0);
    tableWidgetEventFound->resizeColumnToContents(1);
    tableWidgetEventFound->resizeColumnToContents(2);
    if(reset_position){
        tableWidgetEventFound->horizontalScrollBar()->setValue(0);
        tableWidgetEventFound->verticalScrollBar()->setValue(0);
    }else{
        tableWidgetEventFound->horizontalScrollBar()->setValue(orig_hori);
        tableWidgetEventFound->verticalScrollBar()->setValue(orig_vert);
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
                labelEventQuarantinedPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(num)+tr(" (")+QString::number(num)+tr(" entries total)"));
            else
                labelEventQuarantinedPagePosition->setText(QString::number(entriesperpage*page+1)+tr(" - ")+QString::number(entriesperpage*(page+1))+tr(" (")+QString::number(num)+tr(" entries total)"));
        }else{
            labelEventQuarantinedPagePosition->setText(tr("0 - 0 (0 entries total)"));
            return 0;
        }
    }

    query.prepare("SELECT * FROM quarantine_log ORDER BY timestamp DESC LIMIT :lim OFFSET :of ;");
    query.bindValue(":lim", QString::number(entriesperpage, 10));
    query.bindValue(":of", (page)*entriesperpage);
    query.exec();
    while(tableWidgetEventQuarantined->rowCount())
        tableWidgetEventQuarantined->removeRow(0);

    tableWidgetEventQuarantined->horizontalHeaderItem(1)->setTextAlignment(Qt::AlignLeft);
    while(query.next()){
        QTableWidgetItem *item = new QTableWidgetItem(query.value(1).toString());
        if(query.value(1).toString().length() > width)
            width = query.value(1).toString().length();
        tableWidgetEventQuarantined->setColumnWidth(1, width*8);
        tableWidgetEventQuarantined->insertRow(tableWidgetEventQuarantined->rowCount());
        tableWidgetEventQuarantined->setItem(tableWidgetEventQuarantined->rowCount()-1,0,new QTableWidgetItem(
            QDateTime::fromMSecsSinceEpoch(((quint64)query.value(0).toInt())*1000).toString("MM/dd/yyyy hh:mm:ss AP")
        ));
        tableWidgetEventQuarantined->setItem(tableWidgetEventQuarantined->rowCount()-1,1, item);
    }
    tableWidgetEventQuarantined->resizeColumnToContents(1);
    tableWidgetEventQuarantined->horizontalScrollBar()->setValue(0);
    tableWidgetEventQuarantined->verticalScrollBar()->setValue(0);
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
    tableWidgetQuarantine->setEnabled(state);
    pushButtonQuarantineDelete->setEnabled(state);
    pushButtonQuarantineUnQuarantine->setEnabled(state);
    tableWidgetEventQuarantined->setEnabled(state);
    if(state){
        tableWidgetQuarantine->setStyleSheet("background-color: #ffffff;");
        tableWidgetEventQuarantined->setStyleSheet("background-color: #ffffff;");
    }else{
        tableWidgetQuarantine->setStyleSheet("background-color: #eeeeee;");
        tableWidgetEventQuarantined->setStyleSheet("background-color: #eeeeee;");
    }
    quarantineListWidgetEntry->setHidden(!state);
    comboBoxLog->clear();
    if(state){
        comboBoxLog->addItems(QStringList() << "General" << "Detected Threats" << "Quarantined Files");
    }else{
        comboBoxLog->addItems(QStringList() << "General" << "Detected Threats");
    }
    comboBoxLog->setCurrentIndex(0);
    updateGraphsComboBox();
}

void MainWindow::setEnabledSnort(bool state){
    snortListWidgetEntry->setHidden(!state);
    if(state){
        labelStatusEnabledItem5->show();
        labelStatusEnabledItem5Icon->show();
        snortGetLocalVersion();
        snortGetRemoteVersions();
    }else{
        labelStatusEnabledItem5->hide();
        labelStatusEnabledItem5Icon->hide();
    }
    updateGraphsComboBox();
}

void MainWindow::updateGraphsComboBox(){
    comboBoxGraphsSubTitleSelector->clear();
    if(getValDB("enablequarantine") == "yes" && getValDB("enablesnort") == "yes"){
        comboBoxGraphsSubTitleSelector->addItems(QStringList() << "Scanned Files Interval" << "Threats Found Interval" << "Quarantined Files Interval" << "Snort Events Interval");
    }else if(getValDB("enablequarantine") == "yes" && getValDB("enablesnort") != "yes"){
        comboBoxGraphsSubTitleSelector->addItems(QStringList() << "Scanned Files Interval" << "Threats Found Interval" << "Quarantined Files Interval");
    }else if(getValDB("enablequarantine") != "yes" && getValDB("enablesnort") == "yes"){
        comboBoxGraphsSubTitleSelector->addItems(QStringList() << "Scanned Files Interval" << "Threats Found Interval" << "Snort Events Interval");
    }else{
        comboBoxGraphsSubTitleSelector->addItems(QStringList() << "Scanned Files Interval" << "Threats Found Interval");
    }
    comboBoxGraphsSubTitleSelector->setCurrentIndex(0);
    stackedWidgetGraphs->setCurrentIndex(0);
}

void MainWindow::setEnabledOnAccess(bool state){
    if(state){
        labelStatusEnabledItem3->show();
        labelStatusEnabledItem3Icon->show();
    }else{
        labelStatusEnabledItem3->hide();
        labelStatusEnabledItem3Icon->hide();
    }
}

void MainWindow::refreshOinkcode(){
    snortGetRemoteTimeModifiy();
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
    emit sigProcessReadyRead(tr("Scan started...\n").toLocal8Bit());

    QSqlQuery query;
    quint32 ts;
    quint64 count = 0;
    countTotalScanItems(listWidgetToStringList, &count);
    emit sigProcessReadyRead((tr("Files to be scanned: ")+QString::number(count)+"\n").toLocal8Bit());

    ts = (quint32)time(NULL);
    query.prepare("INSERT OR IGNORE INTO counts_table(timestamp, state, num) VALUES (:timestamp1, 1, 0);");
    query.bindValue(":timestamp1", ts);
    query.exec();
    query.prepare("UPDATE counts_table SET num = num + :num1 WHERE timestamp = :timestamp1 AND state = 1 ;");
    query.bindValue(":timestamp1", ts);
    query.bindValue(":num1", count);
    query.exec();
    on_pushButtonGraphsFileScansResetGraph_clicked();
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

void MainWindow::InitializeMainWindow(){
    QMainWindow *qmw = this;
    qmw->setWindowIcon(QIcon("://images/main_icon_grey.png"));
    qmw->setWindowTitle("Clam One");
    qmw->setGeometry(0, 0, 640, 480);
    qmw->setGeometry(QStyle::alignedRect(Qt::LeftToRight, Qt::AlignCenter, qmw->size(), qApp->primaryScreen()->availableGeometry()));
    QWidget *centralWidget = new QWidget();
    qmw->setCentralWidget(centralWidget);
    QVBoxLayout *qvbl = new QVBoxLayout();
    centralWidget->setLayout(qvbl);

    QHBoxLayout *horizontalLayoutTop = new QHBoxLayout();
    horizontalLayoutTop->setSpacing(0);
    QHBoxLayout *horizontalLayoutMiddle = new QHBoxLayout();
    horizontalLayoutMiddle->setSpacing(0);
    QHBoxLayout *horizontalLayoutBottom = new QHBoxLayout();
    horizontalLayoutBottom->setSpacing(0);

    qvbl->addLayout(horizontalLayoutTop);
    qvbl->addLayout(horizontalLayoutMiddle);
    qvbl->addLayout(horizontalLayoutBottom);

    labelTL = new QLabel("Clam One");
    labelTL->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    labelTL->setMinimumWidth(180);
    labelTL->setMaximumHeight(45);
    QFont fontLabel = labelTL->font();
    fontLabel.setPointSize(20);
    fontLabel.setBold(true);
    fontLabel.setUnderline(true);
    labelTL->setFont(fontLabel);
    labelTL->setStyleSheet("background-color: #999999; color: #4A4A4A;");
    labelTL->setAlignment(Qt::AlignHCenter | Qt::AlignVCenter);

    labelTM = new QLabel();
    labelTM->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    labelTM->setStyleSheet("background-color: #999999;");
    labelTM->setScaledContents(true);

    labelTR = new QLabel();
    labelTR->setMaximumHeight(45);
    labelTR->setStyleSheet("background-color: #999999;");
    labelTR->setPixmap(QPixmap("://images/banner_topr.png"));

    horizontalLayoutTop->addWidget(labelTL);
    horizontalLayoutTop->addWidget(labelTM);
    horizontalLayoutTop->addWidget(labelTR);

    listWidget = new QListWidget();
    listWidget->setMinimumWidth(137);
    listWidget->setMaximumWidth(137);
    listWidget->setStyleSheet("background-color: #ffffff; color: #4A4A4A;");
    stackedWidget = new QStackedWidget();
    stackedWidget->setStyleSheet("background-color:#f0f0f0");

    horizontalLayoutMiddle->addWidget(listWidget);
    horizontalLayoutMiddle->addWidget(stackedWidget);

    QLabel *labelBL = new QLabel("Complete<br />Antivirus Solution");
    labelBL->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    labelBL->setMinimumWidth(180);
    labelBL->setMaximumHeight(45);
    fontLabel = labelBL->font();
    fontLabel.setPointSize(12);
    fontLabel.setBold(true);
    labelBL->setFont(fontLabel);
    labelBL->setStyleSheet("background-color: #ababab; color: #4A4A4A;");
    labelBL->setAlignment(Qt::AlignHCenter | Qt::AlignVCenter);

    QLabel *labelBM = new QLabel();
    labelBM->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    labelBM->setStyleSheet("background-color: #ababab;");
    labelBM->setScaledContents(true);

    QLabel *labelBR = new QLabel();
    labelBR->setMaximumHeight(45);
    labelBR->setStyleSheet("background-color: #ababab;");
    labelBR->setPixmap(QPixmap("://images/banner_bottomr.png"));

    horizontalLayoutBottom->addWidget(labelBL);
    horizontalLayoutBottom->addWidget(labelBM);
    horizontalLayoutBottom->addWidget(labelBR);

    new QListWidgetItem(QIcon("://images/icon_scan.png"), "Scanning", listWidget);
    new QListWidgetItem(QIcon("://images/icon_time.png"), "Schedule", listWidget);
    new QListWidgetItem(QIcon("://images/icon_status_grey.png"), "Status", listWidget);
    quarantineListWidgetEntry = new QListWidgetItem(QIcon("://images/icon_quarantine.png"), "Quarantine", listWidget);
    new QListWidgetItem(QIcon("://images/icon_log.png"), "Event Logs", listWidget);
    new QListWidgetItem(QIcon("://images/icon_console.png"), "Messages", listWidget);
    new QListWidgetItem(QIcon("://images/icon_update.png"), "Update", listWidget);
    new QListWidgetItem(QIcon("://images/icon_stats.png"), "Graphs", listWidget);
    new QListWidgetItem(QIcon("://images/icon_setup.png"), "Configure", listWidget);
    snortListWidgetEntry = new QListWidgetItem(QIcon("://images/icon_snort.png"), "Snort", listWidget);
    new QListWidgetItem(QIcon("://images/icon_help.png"), "Help", listWidget);

    QWidget *widgetStackedScan = new QWidget();
    stackedWidget->addWidget(widgetStackedScan);
    QWidget *widgetStackedSchedule = new QWidget();
    stackedWidget->addWidget(widgetStackedSchedule);
    QWidget *widgetStackedStatus = new QWidget();
    stackedWidget->addWidget(widgetStackedStatus);
    QWidget *widgetStackedQuarantine = new QWidget();
    stackedWidget->addWidget(widgetStackedQuarantine);
    QWidget *widgetStackedLogs = new QWidget();
    stackedWidget->addWidget(widgetStackedLogs);
    QWidget *widgetStackedMessages = new QWidget();
    stackedWidget->addWidget(widgetStackedMessages);
    QWidget *widgetStackedUpdate = new QWidget();
    stackedWidget->addWidget(widgetStackedUpdate);
    QWidget *widgetStackedGraphs = new QWidget();
    stackedWidget->addWidget(widgetStackedGraphs);
    QWidget *widgetStackedConfigure = new QWidget();
    stackedWidget->addWidget(widgetStackedConfigure);
    QWidget *widgetStackedSnort = new QWidget();
    stackedWidget->addWidget(widgetStackedSnort);
    QWidget *widgetStackedHelp = new QWidget();
    stackedWidget->addWidget(widgetStackedHelp);

    QVBoxLayout *layoutStack01 = new QVBoxLayout();
    widgetStackedScan->setLayout(layoutStack01);
    {
        QLabel *labelScanTitle = new QLabel("Scan Local Hard Drives");
        labelScanTitle->setStyleSheet("color: #4A4A4A;");
        layoutStack01->addWidget(labelScanTitle);
        fontLabel = labelScanTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelScanTitle->setFont(fontLabel);
        QFrame *frameScan = new QFrame();
        layoutStack01->addWidget(frameScan);
        frameScan->setStyleSheet("background-color: #b6b6b6;");
        frameScan->setFrameShape(QFrame::WinPanel);
        frameScan->setFrameShadow(QFrame::Plain);
        frameScan->setLineWidth(3);
        frameScan->setMidLineWidth(1);
        QGridLayout *scanGridLayout = new QGridLayout();
        frameScan->setLayout(scanGridLayout);
        layoutStack01->addStretch();
        QLabel *labelPointerQuickScan = new QLabel();
        labelScanQuickScan = new QLabel("<a href=\"QuickScan\">Quick Scan</a>");
        connect(labelScanQuickScan, &QLabel::linkActivated, this, &MainWindow::on_labelScanQuickScan_linkActivated);
        QLabel *labelPointerDeepScan = new QLabel();
        labelScanDeepScan = new QLabel("<a href=\"DeepScan\">Deep Scan</a>");
        connect(labelScanDeepScan, &QLabel::linkActivated, this, &MainWindow::on_labelScanDeepScan_linkActivated);
        labelPointerQuickScan->setPixmap(QPixmap("://images/icon_marker.png"));
        labelPointerQuickScan->setMaximumSize(QSize(20, 20));
        labelPointerQuickScan->setScaledContents(true);
        labelPointerDeepScan->setPixmap(QPixmap("://images/icon_marker.png"));
        labelPointerDeepScan->setMaximumSize(QSize(20, 20));
        labelPointerDeepScan->setScaledContents(true);
        scanGridLayout->addWidget(labelPointerQuickScan, 0, 0);
        scanGridLayout->addWidget(labelScanQuickScan, 0, 1);
        scanGridLayout->addWidget(labelPointerDeepScan, 1, 0);
        scanGridLayout->addWidget(labelScanDeepScan, 1, 1);
    }

    QVBoxLayout *layoutStack02 = new QVBoxLayout();
    widgetStackedSchedule->setLayout(layoutStack02);
    {
        QLabel *labelScheduleTitle = new QLabel("Schedule");
        labelScheduleTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelScheduleTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelScheduleTitle->setFont(fontLabel);
        layoutStack02->addWidget(labelScheduleTitle);
        listWidgetSchedule = new QListWidget();
        layoutStack02->addWidget(listWidgetSchedule);
        QHBoxLayout *scheduleHlayout = new QHBoxLayout();
        layoutStack02->addLayout(scheduleHlayout);
        scheduleHlayout->addStretch();
        pushButtonSchedule = new QPushButton("Add New");
        pushButtonSchedule->setFocusPolicy(Qt::NoFocus);
        scheduleHlayout->addWidget(pushButtonSchedule);
        connect(pushButtonSchedule, &QPushButton::clicked, this, &MainWindow::on_pushButtonSchedule_clicked);
    }

    QVBoxLayout *layoutStack03 = new QVBoxLayout();
    widgetStackedStatus->setLayout(layoutStack03);
    {
        QLabel *labelStatusTitle = new QLabel("ClamAV Status");
        labelStatusTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelStatusTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelStatusTitle->setFont(fontLabel);
        layoutStack03->addWidget(labelStatusTitle);
        frameStatus = new QFrame();
        frameStatus->setStyleSheet("background-color: #b6b6b6;");
        frameStatus->setFrameShape(QFrame::WinPanel);
        frameStatus->setFrameShadow(QFrame::Plain);
        frameStatus->setLineWidth(3);
        frameStatus->setMidLineWidth(1);
        layoutStack03->addWidget(frameStatus);
        QVBoxLayout *statusVBoxMain = new QVBoxLayout();
        frameStatus->setLayout(statusVBoxMain);
        labelStatusProtectionState = new QLabel("Protection State");
        labelStatusProtectionState->setWordWrap(true);
        statusVBoxMain->addWidget(labelStatusProtectionState);
        labelStatusProtectionStateDetails = new QLabel("Protection State Details");
        labelStatusProtectionStateDetails->setWordWrap(true);
        statusVBoxMain->addWidget(labelStatusProtectionStateDetails);
        QFrame *hline1 = new QFrame();
        hline1->setFrameShape(QFrame::HLine);
        statusVBoxMain->addWidget(hline1);

        QHBoxLayout *statusHBox1 = new QHBoxLayout();
        statusVBoxMain->addLayout(statusHBox1);
        labelStatusEnabledItem1Icon = new QLabel();
        labelStatusEnabledItem1Icon->setPixmap(QPixmap("://images/ques_16.png"));
        statusHBox1->addWidget(labelStatusEnabledItem1Icon);
        labelStatusEnabledItem1 = new QLabel("Antivirus Engine");
        statusHBox1->addWidget(labelStatusEnabledItem1);
        statusHBox1->addStretch();

        QHBoxLayout *statusHBox2 = new QHBoxLayout();
        statusVBoxMain->addLayout(statusHBox2);
        labelStatusEnabledItem2Icon = new QLabel();
        labelStatusEnabledItem2Icon->setPixmap(QPixmap("://images/ques_16.png"));
        statusHBox2->addWidget(labelStatusEnabledItem2Icon);
        QLabel *labelStatusEnabledItem2 = new QLabel("Antivirus Updater");
        statusHBox2->addWidget(labelStatusEnabledItem2);
        statusHBox2->addStretch();

        QHBoxLayout *statusHBox3 = new QHBoxLayout();
        statusVBoxMain->addLayout(statusHBox3);
        labelStatusEnabledItem3Icon = new QLabel();
        labelStatusEnabledItem3Icon->setPixmap(QPixmap("://images/ques_16.png"));
        statusHBox3->addWidget(labelStatusEnabledItem3Icon);
        labelStatusEnabledItem3 = new QLabel("OnAccess");
        statusHBox3->addWidget(labelStatusEnabledItem3);
        statusHBox3->addStretch();

        QHBoxLayout *statusHBox4 = new QHBoxLayout();
        statusVBoxMain->addLayout(statusHBox4);
        labelStatusEnabledItem4Icon = new QLabel();
        labelStatusEnabledItem4Icon->setPixmap(QPixmap("://images/ques_16.png"));
        statusHBox4->addWidget(labelStatusEnabledItem4Icon);
        labelStatusEnabledItem4 = new QLabel("Not Applicable");
        statusHBox4->addWidget(labelStatusEnabledItem4);
        statusHBox4->addStretch();

        labelStatusEnabledItem4->hide();
        labelStatusEnabledItem4Icon->hide();

        QHBoxLayout *statusHBox5 = new QHBoxLayout();
        statusVBoxMain->addLayout(statusHBox5);
        labelStatusEnabledItem5Icon = new QLabel();
        labelStatusEnabledItem5Icon->setPixmap(QPixmap("://images/ques_16.png"));
        statusHBox5->addWidget(labelStatusEnabledItem5Icon);
        labelStatusEnabledItem5 = new QLabel("Snort Network Intrusion Detection System");
        statusHBox5->addWidget(labelStatusEnabledItem5);
        statusHBox5->addStretch();

        QFrame *hline2 = new QFrame();
        hline2->setFrameShape(QFrame::HLine);
        statusVBoxMain->addWidget(hline2);

        QHBoxLayout *statusHBox6 = new QHBoxLayout();
        statusVBoxMain->addLayout(statusHBox6);
        QLabel *labelNumBlockedAttacksName = new QLabel("New Events Detected:");
        statusHBox6->addWidget(labelNumBlockedAttacksName);
        labelNumBlockedAttacksVal = new QLabel("0");
        connect(labelNumBlockedAttacksVal, &QLabel::linkActivated, this, &MainWindow::on_labelNumBlockedAttacksVal_linkActivated);
        labelNumBlockedAttacksVal->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
        statusHBox6->addWidget(labelNumBlockedAttacksVal);

        layoutStack03->addStretch();
    }

    QVBoxLayout *layoutStack04 = new QVBoxLayout();
    widgetStackedQuarantine->setLayout(layoutStack04);
    {
      QLabel *labelQuarantineTitle = new QLabel("Quarantined Files");
      labelQuarantineTitle->setStyleSheet("color: #4A4A4A;");
      fontLabel = labelQuarantineTitle->font();
      fontLabel.setPointSize(20);
      fontLabel.setBold(true);
      labelQuarantineTitle->setFont(fontLabel);
      layoutStack04->addWidget(labelQuarantineTitle);
      QLabel *labelQuarantineSubTitle = new QLabel();
      labelQuarantineSubTitle->setText(
            "<html><head/><body><p>This is the area that contains files that are quarantined, "
            "it can be potential malware detected by ClamAV but rendered &quot;non-active&quot;. "
            "If you are sure you want to delete any quarantined file, you can permently delete it "
            "from here.</p><p>Large files may take a long time to quarantine, unquarantine, and may "
            "cause long load times of Clam One.</p></body></html>");
      labelQuarantineSubTitle->setWordWrap(true);
      layoutStack04->addWidget(labelQuarantineSubTitle);
      tableWidgetQuarantine = new QTableWidget();
      layoutStack04->addWidget(tableWidgetQuarantine);
      tableWidgetQuarantine->setColumnCount(4);
      tableWidgetQuarantine->setHorizontalHeaderLabels(QStringList() << "File Name" << "Date/Time" << "File Size" << "Quarantine Name");
      tableWidgetQuarantine->setStyleSheet("background-color: #ffffff;");
      tableWidgetQuarantine->setAlternatingRowColors(true);
      tableWidgetQuarantine->setSelectionMode(QAbstractItemView::SingleSelection);
      tableWidgetQuarantine->setSelectionBehavior(QAbstractItemView::SelectRows);
      tableWidgetQuarantine->setTextElideMode(Qt::ElideNone);
      tableWidgetQuarantine->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
      tableWidgetQuarantine->horizontalHeader()->setDefaultSectionSize(150);
      tableWidgetQuarantine->horizontalHeader()->setStretchLastSection(true);
      QHBoxLayout *quarantineHBox1 = new QHBoxLayout();
      layoutStack04->addLayout(quarantineHBox1);
      quarantineHBox1->addStretch();
      pushButtonQuarantineUnQuarantine = new QPushButton("UnQuarantine File");
      pushButtonQuarantineUnQuarantine->setFocusPolicy(Qt::NoFocus);
      quarantineHBox1->addWidget(pushButtonQuarantineUnQuarantine);
      pushButtonQuarantineDelete = new QPushButton("Permanently Delete File");
      pushButtonQuarantineDelete->setFocusPolicy(Qt::NoFocus);
      quarantineHBox1->addWidget(pushButtonQuarantineDelete);
    }
    QVBoxLayout *layoutStack05 = new QVBoxLayout();
    widgetStackedLogs->setLayout(layoutStack05);
    {
      QLabel *labelLogTitle = new QLabel("Event Logs");
      labelLogTitle->setStyleSheet("color: #4A4A4A;");
      fontLabel = labelLogTitle->font();
      fontLabel.setPointSize(20);
      fontLabel.setBold(true);
      labelLogTitle->setFont(fontLabel);
      layoutStack05->addWidget(labelLogTitle);
      layoutStack05->addStretch();
      QHBoxLayout *eventGeneralHBox1 = new QHBoxLayout();
      layoutStack05->addLayout(eventGeneralHBox1);
      QLabel *labelLogTypeName = new QLabel("Type: ");
      eventGeneralHBox1->addWidget(labelLogTypeName);
      comboBoxLog = new QComboBox();
      comboBoxLog->setMinimumWidth(200);
      if(getValDB("enablequarantine")=="yes"){
          comboBoxLog->addItems(QStringList() << "General" << "Detected Threats" << "Quarantined Files");
      }else{
          comboBoxLog->addItems(QStringList() << "General" << "Detected Threats");
      }
      eventGeneralHBox1->addWidget(comboBoxLog);
      eventGeneralHBox1->addStretch();

      stackedWidgetEvents = new QStackedWidget();
      layoutStack05->addWidget(stackedWidgetEvents);
      {
          QWidget *stackedEventGeneral = new QWidget();
          stackedWidgetEvents->addWidget(stackedEventGeneral);
          {
              QVBoxLayout *vboxEventGeneral = new QVBoxLayout();
              stackedEventGeneral->setLayout(vboxEventGeneral);

              tableWidgetEventGeneral = new QTableWidget();
              tableWidgetEventGeneral->setColumnCount(2);
              tableWidgetEventGeneral->setHorizontalHeaderItem(0, new QTableWidgetItem("Time"));
              tableWidgetEventGeneral->setHorizontalHeaderItem(1, new QTableWidgetItem("Message"));
              tableWidgetEventGeneral->setAlternatingRowColors(true);
              tableWidgetEventGeneral->setSelectionMode(QAbstractItemView::NoSelection);
              tableWidgetEventGeneral->setTextElideMode(Qt::ElideNone);
              tableWidgetEventGeneral->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
              tableWidgetEventGeneral->horizontalHeader()->setMinimumSectionSize(160);
              tableWidgetEventGeneral->horizontalHeader()->setStretchLastSection(true);
              tableWidgetEventGeneral->verticalHeader()->setVisible(false);
              tableWidgetEventGeneral->horizontalHeader()->setVisible(true);
              tableWidgetEventGeneral->setStyleSheet("background-color: #ffffff;");
              vboxEventGeneral->addWidget(tableWidgetEventGeneral);

              QHBoxLayout *hboxEventGeneral = new QHBoxLayout();
              vboxEventGeneral->addLayout(hboxEventGeneral);
              hboxEventGeneral->addStretch();
              labelEventGeneralPagePosition = new QLabel("0/0");
              hboxEventGeneral->addWidget(labelEventGeneralPagePosition);
              hboxEventGeneral->addStretch();
              hboxEventGeneral->addStretch();
              QPushButton *pushButtonEventGeneralPageBegining = new QPushButton();
              connect(pushButtonEventGeneralPageBegining, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventGeneralPageBegining_clicked);
              pushButtonEventGeneralPageBegining->setFocusPolicy(Qt::NoFocus);
              pushButtonEventGeneralPageBegining->setMaximumWidth(26);
              pushButtonEventGeneralPageBegining->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
              hboxEventGeneral->addWidget(pushButtonEventGeneralPageBegining);
              QPushButton *pushButtonEventGeneralPageBack = new QPushButton();
              connect(pushButtonEventGeneralPageBack, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventGeneralPageBack_clicked);
              pushButtonEventGeneralPageBack->setFocusPolicy(Qt::NoFocus);
              pushButtonEventGeneralPageBack->setMaximumWidth(13);
              pushButtonEventGeneralPageBack->setIcon(QIcon(QPixmap(":/images/left.png")));
              hboxEventGeneral->addWidget(pushButtonEventGeneralPageBack);
              QPushButton *pushButtonEventGeneralPageForward = new QPushButton();
              connect(pushButtonEventGeneralPageForward, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventGeneralPageForward_clicked);
              pushButtonEventGeneralPageForward->setFocusPolicy(Qt::NoFocus);
              pushButtonEventGeneralPageForward->setMaximumWidth(13);
              pushButtonEventGeneralPageForward->setIcon(QIcon(QPixmap(":/images/right.png")));
              hboxEventGeneral->addWidget(pushButtonEventGeneralPageForward);
              QPushButton *pushButtonEventGeneralPageEnd = new QPushButton();
              connect(pushButtonEventGeneralPageEnd, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventGeneralPageEnd_clicked);
              pushButtonEventGeneralPageEnd->setFocusPolicy(Qt::NoFocus);
              pushButtonEventGeneralPageEnd->setMaximumWidth(26);
              pushButtonEventGeneralPageEnd->setIcon(QIcon(QPixmap(":/images/rightright.png")));
              hboxEventGeneral->addWidget(pushButtonEventGeneralPageEnd);
          }

          QWidget *stackedEventFound = new QWidget();
          stackedWidgetEvents->addWidget(stackedEventFound);
          {
              QVBoxLayout *vboxEventFound = new QVBoxLayout();
              stackedEventFound->setLayout(vboxEventFound);

              tableWidgetEventFound = new QTableWidget();
              tableWidgetEventFound->setColumnCount(2);
              tableWidgetEventFound->setHorizontalHeaderItem(0, new QTableWidgetItem("Time"));
              tableWidgetEventFound->setHorizontalHeaderItem(1, new QTableWidgetItem("Message"));
              tableWidgetEventFound->setAlternatingRowColors(true);
              tableWidgetEventFound->setSelectionMode(QAbstractItemView::NoSelection);
              tableWidgetEventFound->setTextElideMode(Qt::ElideNone);
              tableWidgetEventFound->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
              tableWidgetEventFound->horizontalHeader()->setMinimumSectionSize(160);
              tableWidgetEventFound->horizontalHeader()->setStretchLastSection(true);
              tableWidgetEventFound->verticalHeader()->setVisible(false);
              tableWidgetEventFound->horizontalHeader()->setVisible(true);
              tableWidgetEventFound->setStyleSheet("background-color: #ffffff;");
              vboxEventFound->addWidget(tableWidgetEventFound);

              QHBoxLayout *hboxEventFound = new QHBoxLayout();
              vboxEventFound->addLayout(hboxEventFound);
              hboxEventFound->addStretch();
              labelEventFoundPagePosition = new QLabel("0/0");
              hboxEventFound->addWidget(labelEventFoundPagePosition);
              hboxEventFound->addStretch();
              hboxEventFound->addStretch();
              QPushButton *pushButtonEventFoundPageBegining = new QPushButton();
              connect(pushButtonEventFoundPageBegining, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventFoundPageBegining_clicked);
              pushButtonEventFoundPageBegining->setFocusPolicy(Qt::NoFocus);
              pushButtonEventFoundPageBegining->setMaximumWidth(26);
              pushButtonEventFoundPageBegining->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
              hboxEventFound->addWidget(pushButtonEventFoundPageBegining);
              QPushButton *pushButtonEventFoundPageBack = new QPushButton();
              connect(pushButtonEventFoundPageBack, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventFoundPageBack_clicked);
              pushButtonEventFoundPageBack->setFocusPolicy(Qt::NoFocus);
              pushButtonEventFoundPageBack->setMaximumWidth(13);
              pushButtonEventFoundPageBack->setIcon(QIcon(QPixmap(":/images/left.png")));
              hboxEventFound->addWidget(pushButtonEventFoundPageBack);
              QPushButton *pushButtonEventFoundPageForward = new QPushButton();
              connect(pushButtonEventFoundPageForward, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventFoundPageForward_clicked);
              pushButtonEventFoundPageForward->setFocusPolicy(Qt::NoFocus);
              pushButtonEventFoundPageForward->setMaximumWidth(13);
              pushButtonEventFoundPageForward->setIcon(QIcon(QPixmap(":/images/right.png")));
              hboxEventFound->addWidget(pushButtonEventFoundPageForward);
              QPushButton *pushButtonEventFoundPageEnd = new QPushButton();
              connect(pushButtonEventFoundPageEnd, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventFoundPageEnd_clicked);
              pushButtonEventFoundPageEnd->setFocusPolicy(Qt::NoFocus);
              pushButtonEventFoundPageEnd->setMaximumWidth(26);
              pushButtonEventFoundPageEnd->setIcon(QIcon(QPixmap(":/images/rightright.png")));
              hboxEventFound->addWidget(pushButtonEventFoundPageEnd);
          }

          QWidget *stackedEventQuarantined = new QWidget();
          stackedWidgetEvents->addWidget(stackedEventQuarantined);
          {
              QVBoxLayout *vboxEventQuarantined = new QVBoxLayout();
              stackedEventQuarantined->setLayout(vboxEventQuarantined);

              tableWidgetEventQuarantined = new QTableWidget();
              tableWidgetEventQuarantined->setColumnCount(2);
              tableWidgetEventQuarantined->setHorizontalHeaderItem(0, new QTableWidgetItem("Time"));
              tableWidgetEventQuarantined->setHorizontalHeaderItem(1, new QTableWidgetItem("Message"));
              tableWidgetEventQuarantined->setAlternatingRowColors(true);
              tableWidgetEventQuarantined->setSelectionMode(QAbstractItemView::NoSelection);
              tableWidgetEventQuarantined->setTextElideMode(Qt::ElideNone);
              tableWidgetEventQuarantined->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
              tableWidgetEventQuarantined->horizontalHeader()->setMinimumSectionSize(160);
              tableWidgetEventQuarantined->horizontalHeader()->setStretchLastSection(true);
              tableWidgetEventQuarantined->verticalHeader()->setVisible(false);
              tableWidgetEventQuarantined->horizontalHeader()->setVisible(true);
              tableWidgetEventQuarantined->setStyleSheet("background-color: #ffffff;");
              vboxEventQuarantined->addWidget(tableWidgetEventQuarantined);

              QHBoxLayout *hboxEventQuarantined = new QHBoxLayout();
              vboxEventQuarantined->addLayout(hboxEventQuarantined);
              hboxEventQuarantined->addStretch();
              labelEventQuarantinedPagePosition = new QLabel("0/0");
              hboxEventQuarantined->addWidget(labelEventQuarantinedPagePosition);
              hboxEventQuarantined->addStretch();
              hboxEventQuarantined->addStretch();
              QPushButton *pushButtonEventQuarantinedPageBegining = new QPushButton();
              connect(pushButtonEventQuarantinedPageBegining, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventQuarantinedPageBegining_clicked);
              pushButtonEventQuarantinedPageBegining->setFocusPolicy(Qt::NoFocus);
              pushButtonEventQuarantinedPageBegining->setMaximumWidth(26);
              pushButtonEventQuarantinedPageBegining->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
              hboxEventQuarantined->addWidget(pushButtonEventQuarantinedPageBegining);
              QPushButton *pushButtonEventQuarantinedPageBack = new QPushButton();
              connect(pushButtonEventQuarantinedPageBack, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventQuarantinedPageBack_clicked);
              pushButtonEventQuarantinedPageBack->setFocusPolicy(Qt::NoFocus);
              pushButtonEventQuarantinedPageBack->setMaximumWidth(13);
              pushButtonEventQuarantinedPageBack->setIcon(QIcon(QPixmap(":/images/left.png")));
              hboxEventQuarantined->addWidget(pushButtonEventQuarantinedPageBack);
              QPushButton *pushButtonEventQuarantinedPageForward = new QPushButton();
              connect(pushButtonEventQuarantinedPageForward, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventQuarantinedPageForward_clicked);
              pushButtonEventQuarantinedPageForward->setFocusPolicy(Qt::NoFocus);
              pushButtonEventQuarantinedPageForward->setMaximumWidth(13);
              pushButtonEventQuarantinedPageForward->setIcon(QIcon(QPixmap(":/images/right.png")));
              hboxEventQuarantined->addWidget(pushButtonEventQuarantinedPageForward);
              QPushButton *pushButtonEventQuarantinedPageEnd = new QPushButton();
              connect(pushButtonEventQuarantinedPageEnd, &QPushButton::clicked, this, &MainWindow::on_pushButtonEventQuarantinedPageEnd_clicked);
              pushButtonEventQuarantinedPageEnd->setFocusPolicy(Qt::NoFocus);
              pushButtonEventQuarantinedPageEnd->setMaximumWidth(26);
              pushButtonEventQuarantinedPageEnd->setIcon(QIcon(QPixmap(":/images/rightright.png")));
              hboxEventQuarantined->addWidget(pushButtonEventQuarantinedPageEnd);
          }
          stackedWidgetEvents->setCurrentIndex(0);
          comboBoxLog->setCurrentIndex(0);
          connect(comboBoxLog, QOverload<int>::of(&QComboBox::activated), stackedWidgetEvents, &QStackedWidget::setCurrentIndex);
      }
    }

    QVBoxLayout *layoutStack06 = new QVBoxLayout();
    widgetStackedMessages->setLayout(layoutStack06);
    {
        QLabel *labelMessagesTitle = new QLabel("Messages");
        labelMessagesTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelMessagesTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelMessagesTitle->setFont(fontLabel);
        layoutStack06->addWidget(labelMessagesTitle);
        tableWidgetMessages = new QTableWidget();
        tableWidgetMessages->setColumnCount(2);
        tableWidgetMessages->setHorizontalHeaderItem(0, new QTableWidgetItem("Time"));
        tableWidgetMessages->setHorizontalHeaderItem(1, new QTableWidgetItem("Console Messages"));
        tableWidgetMessages->setAlternatingRowColors(true);
        tableWidgetMessages->setSelectionMode(QAbstractItemView::NoSelection);
        tableWidgetMessages->setTextElideMode(Qt::ElideNone);
        tableWidgetMessages->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        tableWidgetMessages->horizontalHeader()->setMinimumSectionSize(160);
        tableWidgetMessages->horizontalHeader()->setStretchLastSection(true);
        tableWidgetMessages->verticalHeader()->setVisible(false);
        tableWidgetMessages->horizontalHeader()->setVisible(true);

        tableWidgetMessages->setStyleSheet("background-color: #ffffff;");
        layoutStack06->addWidget(tableWidgetMessages);

        QHBoxLayout *hboxMessages = new QHBoxLayout();
        layoutStack06->addLayout(hboxMessages);
        hboxMessages->addStretch();
        labelMessagesPagePosition = new QLabel("0/0");
        hboxMessages->addWidget(labelMessagesPagePosition);
        hboxMessages->addStretch();
        hboxMessages->addStretch();
        QPushButton *pushButtonMessagesPageBegining = new QPushButton();
        connect(pushButtonMessagesPageBegining, &QPushButton::clicked, this, &MainWindow::on_pushButtonMessagesPageBegining_clicked);
        pushButtonMessagesPageBegining->setFocusPolicy(Qt::NoFocus);
        pushButtonMessagesPageBegining->setMaximumWidth(26);
        pushButtonMessagesPageBegining->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
        hboxMessages->addWidget(pushButtonMessagesPageBegining);
        QPushButton *pushButtonMessagesPageBack = new QPushButton();
        connect(pushButtonMessagesPageBack, &QPushButton::clicked, this, &MainWindow::on_pushButtonMessagesPageBack_clicked);
        pushButtonMessagesPageBack->setFocusPolicy(Qt::NoFocus);
        pushButtonMessagesPageBack->setMaximumWidth(13);
        pushButtonMessagesPageBack->setIcon(QIcon(QPixmap(":/images/left.png")));
        hboxMessages->addWidget(pushButtonMessagesPageBack);
        QPushButton *pushButtonMessagesPageForward = new QPushButton();
        connect(pushButtonMessagesPageForward, &QPushButton::clicked, this, &MainWindow::on_pushButtonMessagesPageForward_clicked);
        pushButtonMessagesPageForward->setFocusPolicy(Qt::NoFocus);
        pushButtonMessagesPageForward->setMaximumWidth(13);
        pushButtonMessagesPageForward->setIcon(QIcon(QPixmap(":/images/right.png")));
        hboxMessages->addWidget(pushButtonMessagesPageForward);
        QPushButton *pushButtonMessagesPageEnd = new QPushButton();
        connect(pushButtonMessagesPageEnd, &QPushButton::clicked, this, &MainWindow::on_pushButtonMessagesPageEnd_clicked);
        pushButtonMessagesPageEnd->setFocusPolicy(Qt::NoFocus);
        pushButtonMessagesPageEnd->setMaximumWidth(26);
        pushButtonMessagesPageEnd->setIcon(QIcon(QPixmap(":/images/rightright.png")));
        hboxMessages->addWidget(pushButtonMessagesPageEnd);

    }

    QVBoxLayout *layoutStack07 = new QVBoxLayout();
    widgetStackedUpdate->setLayout(layoutStack07);
    {
        labelUpdateMessage = new QLabel("Virus update status");
        labelUpdateMessage->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelUpdateMessage->font();
        fontLabel.setPointSize(13);
        fontLabel.setBold(true);
        labelUpdateMessage->setFont(fontLabel);
        layoutStack07->addWidget(labelUpdateMessage);
        frameUpdate = new QFrame();
        frameUpdate->setStyleSheet("background-color: #b6b6b6;");
        frameUpdate->setFrameShadow(QFrame::Plain);
        frameUpdate->setFrameShape(QFrame::WinPanel);
        layoutStack07->addWidget(frameUpdate);
        QVBoxLayout *vboxframeUpdate = new QVBoxLayout();
        frameUpdate->setLayout(vboxframeUpdate);
        labelUpdateMessageDetails = new QLabel("Default");
        labelUpdateMessageDetails->setWordWrap(true);
        vboxframeUpdate->addWidget(labelUpdateMessageDetails);

        QFrame *hline1 = new QFrame();
        hline1->setFrameShape(QFrame::HLine);
        hline1->setFrameShadow(QFrame::Sunken);
        vboxframeUpdate->addWidget(hline1);

        QHBoxLayout *hboxFrameUpdate1 = new QHBoxLayout();
        vboxframeUpdate->addLayout(hboxFrameUpdate1);
        QLabel *labelUpdateLocalDailyName = new QLabel("Local daily.cld:");
        hboxFrameUpdate1->addWidget(labelUpdateLocalDailyName);
        labelUpdateLocalDailyVal = new QLabel("");
        hboxFrameUpdate1->addWidget(labelUpdateLocalDailyVal);

        QHBoxLayout *hboxFrameUpdate2 = new QHBoxLayout();
        vboxframeUpdate->addLayout(hboxFrameUpdate2);
        QLabel *labelUpdateLocalMainName = new QLabel("Local main.cld:");
        hboxFrameUpdate2->addWidget(labelUpdateLocalMainName);
        labelUpdateLocalMainVal = new QLabel("");
        hboxFrameUpdate2->addWidget(labelUpdateLocalMainVal);

        QHBoxLayout *hboxFrameUpdate3 = new QHBoxLayout();
        vboxframeUpdate->addLayout(hboxFrameUpdate3);
        QLabel *labelUpdateLocalByteName = new QLabel("Local bytecode.cld:");
        hboxFrameUpdate3->addWidget(labelUpdateLocalByteName);
        labelUpdateLocalByteVal = new QLabel("");
        hboxFrameUpdate3->addWidget(labelUpdateLocalByteVal);

        QHBoxLayout *hboxFrameUpdate4 = new QHBoxLayout();
        vboxframeUpdate->addLayout(hboxFrameUpdate4);
        QLabel *labelUpdateRemoteVersionName = new QLabel("Remote definition version:");
        hboxFrameUpdate4->addWidget(labelUpdateRemoteVersionName);
        labelUpdateRemoteVersionVal = new QLabel("");
        hboxFrameUpdate4->addWidget(labelUpdateRemoteVersionVal);

        QFrame *hline2 = new QFrame();
        hline2->setFrameShape(QFrame::HLine);
        hline2->setFrameShadow(QFrame::Sunken);
        vboxframeUpdate->addWidget(hline2);

        QHBoxLayout *hboxFrameUpdate5 = new QHBoxLayout();
        vboxframeUpdate->addLayout(hboxFrameUpdate5);
        QLabel *labelUpdateLocalEngineName = new QLabel("Local engine version:");
        hboxFrameUpdate5->addWidget(labelUpdateLocalEngineName);
        labelUpdateLocalEngineVal = new QLabel("");
        hboxFrameUpdate5->addWidget(labelUpdateLocalEngineVal);

        QHBoxLayout *hboxFrameUpdate6 = new QHBoxLayout();
        vboxframeUpdate->addLayout(hboxFrameUpdate6);
        QLabel *labelUpdateRemoteEngineName = new QLabel("Remote engine version:");
        hboxFrameUpdate6->addWidget(labelUpdateRemoteEngineName);
        labelUpdateRemoteEngineVal = new QLabel("");
        hboxFrameUpdate6->addWidget(labelUpdateRemoteEngineVal);

        QFrame *hline3 = new QFrame();
        hline3->setFrameShape(QFrame::HLine);
        hline3->setFrameShadow(QFrame::Sunken);
        vboxframeUpdate->addWidget(hline3);

        labelUpdateClickUpdateDefs = new QLabel("Using the &quot;kill&quot; command, send a signal to the "
                                                "freshclam daemon to<br /><a href=\"UpdateVirusDefinitions\">"
                                                "Update virus definitions</a>");
        connect(labelUpdateClickUpdateDefs, &QLabel::linkActivated, this, &MainWindow::on_labelUpdateClickUpdateDefs_linkActivated);
        vboxframeUpdate->addWidget(labelUpdateClickUpdateDefs);

        layoutStack07->addStretch();
    }

    QVBoxLayout *layoutStack08 = new QVBoxLayout();
    widgetStackedGraphs->setLayout(layoutStack08);
    {
        QLabel *labelGraphsTitle = new QLabel("Graphs");
        labelGraphsTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelGraphsTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelGraphsTitle->setFont(fontLabel);
        layoutStack08->addWidget(labelGraphsTitle);

        QHBoxLayout *hboxGraphs1 = new QHBoxLayout();
        layoutStack08->addLayout(hboxGraphs1);
        QLabel *labelGraphsSubTitleName = new QLabel("Plot Type");
        hboxGraphs1->addWidget(labelGraphsSubTitleName);
        comboBoxGraphsSubTitleSelector = new QComboBox();
        comboBoxGraphsSubTitleSelector->addItems(QStringList() << "Scanned Files Interval" << "Threats Found Interval");

        hboxGraphs1->addWidget(comboBoxGraphsSubTitleSelector);
        hboxGraphs1->addStretch();

        stackedWidgetGraphs = new QStackedWidget();
        layoutStack08->addWidget(stackedWidgetGraphs);

        {
            QWidget *pageScanedFiles = new QWidget();
            stackedWidgetGraphs->addWidget(pageScanedFiles);
            QVBoxLayout *vboxPageScanedFiles = new QVBoxLayout();
            pageScanedFiles->setLayout(vboxPageScanedFiles);

            chartviewScanedFiles = new QChartView();
            chartviewScanedFiles->setRenderHint(QPainter::Antialiasing);
            chartviewScanedFiles->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            vboxPageScanedFiles->addWidget(chartviewScanedFiles);

            QHBoxLayout *hboxPageScanedFiles = new QHBoxLayout();
            vboxPageScanedFiles->addLayout(hboxPageScanedFiles);
            hboxPageScanedFiles->addStretch();
            labelGraphsScanedXYPosition1 = new QLabel("1");
            hboxPageScanedFiles->addWidget(labelGraphsScanedXYPosition1);
            hboxPageScanedFiles->addStretch();
            labelGraphsScanedXYPosition2 = new QLabel("2");
            hboxPageScanedFiles->addWidget(labelGraphsScanedXYPosition2);
            hboxPageScanedFiles->addStretch();
            QPushButton *pushButtonGraphsFileScansResetGraph = new QPushButton();
            connect(pushButtonGraphsFileScansResetGraph, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileScansResetGraph_clicked);
            pushButtonGraphsFileScansResetGraph->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileScansResetGraph->setMaximumWidth(26);
            pushButtonGraphsFileScansResetGraph->setIcon(QIcon(QPixmap(":/images/reset.png")));
            hboxPageScanedFiles->addWidget(pushButtonGraphsFileScansResetGraph);
            QPushButton *pushButtonGraphsFileScansXshiftup = new QPushButton();
            connect(pushButtonGraphsFileScansXshiftup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileScansXshiftup_clicked);
            pushButtonGraphsFileScansXshiftup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileScansXshiftup->setMaximumWidth(26);
            pushButtonGraphsFileScansXshiftup->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
            hboxPageScanedFiles->addWidget(pushButtonGraphsFileScansXshiftup);
            QPushButton *pushButtonGraphsFileScansXscaleup = new QPushButton();
            connect(pushButtonGraphsFileScansXscaleup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileScansXscaleup_clicked);
            pushButtonGraphsFileScansXscaleup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileScansXscaleup->setMaximumWidth(13);
            pushButtonGraphsFileScansXscaleup->setIcon(QIcon(QPixmap(":/images/left.png")));
            hboxPageScanedFiles->addWidget(pushButtonGraphsFileScansXscaleup);
            QPushButton *pushButtonGraphsFileScansXscaledown = new QPushButton();
            connect(pushButtonGraphsFileScansXscaledown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileScansXscaledown_clicked);
            pushButtonGraphsFileScansXscaledown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileScansXscaledown->setMaximumWidth(13);
            pushButtonGraphsFileScansXscaledown->setIcon(QIcon(QPixmap(":/images/right.png")));
            hboxPageScanedFiles->addWidget(pushButtonGraphsFileScansXscaledown);
            QPushButton *pushButtonGraphsFileScansXshiftdown = new QPushButton();
            connect(pushButtonGraphsFileScansXshiftdown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileScansXshiftdown_clicked);
            pushButtonGraphsFileScansXshiftdown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileScansXshiftdown->setMaximumWidth(26);
            pushButtonGraphsFileScansXshiftdown->setIcon(QIcon(QPixmap(":/images/rightright.png")));
            hboxPageScanedFiles->addWidget(pushButtonGraphsFileScansXshiftdown);
        }

        {
            QWidget *pageThreatsFound = new QWidget();
            stackedWidgetGraphs->addWidget(pageThreatsFound);

            QVBoxLayout *vboxPageThreatsFound = new QVBoxLayout();
            pageThreatsFound->setLayout(vboxPageThreatsFound);

            chartviewThreatsFound = new QChartView();
            chartviewThreatsFound->setRenderHint(QPainter::Antialiasing);
            chartviewThreatsFound->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            vboxPageThreatsFound->addWidget(chartviewThreatsFound);

            QHBoxLayout *hboxPageThreatsFound = new QHBoxLayout();
            vboxPageThreatsFound->addLayout(hboxPageThreatsFound);
            hboxPageThreatsFound->addStretch();
            labelGraphsFoundXYPosition1 = new QLabel("1");
            hboxPageThreatsFound->addWidget(labelGraphsFoundXYPosition1);
            hboxPageThreatsFound->addStretch();
            labelGraphsFoundXYPosition2 = new QLabel("2");
            hboxPageThreatsFound->addWidget(labelGraphsFoundXYPosition2);
            hboxPageThreatsFound->addStretch();
            QPushButton *pushButtonGraphsFileFoundResetGraph = new QPushButton();
            connect(pushButtonGraphsFileFoundResetGraph, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileFoundResetGraph_clicked);
            pushButtonGraphsFileFoundResetGraph->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileFoundResetGraph->setMaximumWidth(26);
            pushButtonGraphsFileFoundResetGraph->setIcon(QIcon(QPixmap(":/images/reset.png")));
            hboxPageThreatsFound->addWidget(pushButtonGraphsFileFoundResetGraph);
            QPushButton *pushButtonGraphsFileFoundXshiftup = new QPushButton();
            connect(pushButtonGraphsFileFoundXshiftup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileFoundXshiftup_clicked);
            pushButtonGraphsFileFoundXshiftup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileFoundXshiftup->setMaximumWidth(26);
            pushButtonGraphsFileFoundXshiftup->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
            hboxPageThreatsFound->addWidget(pushButtonGraphsFileFoundXshiftup);
            QPushButton *pushButtonGraphsFileFoundXscaleup = new QPushButton();
            connect(pushButtonGraphsFileFoundXscaleup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileFoundXscaleup_clicked);
            pushButtonGraphsFileFoundXscaleup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileFoundXscaleup->setMaximumWidth(13);
            pushButtonGraphsFileFoundXscaleup->setIcon(QIcon(QPixmap(":/images/left.png")));
            hboxPageThreatsFound->addWidget(pushButtonGraphsFileFoundXscaleup);
            QPushButton *pushButtonGraphsFileFoundXscaledown = new QPushButton();
            connect(pushButtonGraphsFileFoundXscaledown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileFoundXscaledown_clicked);
            pushButtonGraphsFileFoundXscaledown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileFoundXscaledown->setMaximumWidth(13);
            pushButtonGraphsFileFoundXscaledown->setIcon(QIcon(QPixmap(":/images/right.png")));
            hboxPageThreatsFound->addWidget(pushButtonGraphsFileFoundXscaledown);
            QPushButton *pushButtonGraphsFileFoundXshiftdown = new QPushButton();
            connect(pushButtonGraphsFileFoundXshiftdown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileFoundXshiftdown_clicked);
            pushButtonGraphsFileFoundXshiftdown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileFoundXshiftdown->setMaximumWidth(26);
            pushButtonGraphsFileFoundXshiftdown->setIcon(QIcon(QPixmap(":/images/rightright.png")));
            hboxPageThreatsFound->addWidget(pushButtonGraphsFileFoundXshiftdown);

        }

        {
            QWidget *pageQuarantinedFiles = new QWidget();
            stackedWidgetGraphs->addWidget(pageQuarantinedFiles);
            QVBoxLayout *vboxPageQuarantinedFiles = new QVBoxLayout();
            pageQuarantinedFiles->setLayout(vboxPageQuarantinedFiles);

            chartviewQuarantinedFiles = new QChartView();
            chartviewQuarantinedFiles->setRenderHint(QPainter::Antialiasing);
            chartviewQuarantinedFiles->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            vboxPageQuarantinedFiles->addWidget(chartviewQuarantinedFiles);

            QHBoxLayout *hboxPageQuarantinedFiles = new QHBoxLayout();
            vboxPageQuarantinedFiles->addLayout(hboxPageQuarantinedFiles);
            hboxPageQuarantinedFiles->addStretch();
            labelGraphsQuarantineXYPosition1 = new QLabel("1");
            hboxPageQuarantinedFiles->addWidget(labelGraphsQuarantineXYPosition1);
            hboxPageQuarantinedFiles->addStretch();
            labelGraphsQuarantineXYPosition2 = new QLabel("2");
            hboxPageQuarantinedFiles->addWidget(labelGraphsQuarantineXYPosition2);
            hboxPageQuarantinedFiles->addStretch();
            QPushButton *pushButtonGraphsFileQuarantineResetGraph = new QPushButton();
            connect(pushButtonGraphsFileQuarantineResetGraph, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileQuarantineResetGraph_clicked);
            pushButtonGraphsFileQuarantineResetGraph->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileQuarantineResetGraph->setMaximumWidth(26);
            pushButtonGraphsFileQuarantineResetGraph->setIcon(QIcon(QPixmap(":/images/reset.png")));
            hboxPageQuarantinedFiles->addWidget(pushButtonGraphsFileQuarantineResetGraph);
            QPushButton *pushButtonGraphsFileQuarantineXshiftup = new QPushButton();
            connect(pushButtonGraphsFileQuarantineXshiftup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileQuarantineXshiftup_clicked);
            pushButtonGraphsFileQuarantineXshiftup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileQuarantineXshiftup->setMaximumWidth(26);
            pushButtonGraphsFileQuarantineXshiftup->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
            hboxPageQuarantinedFiles->addWidget(pushButtonGraphsFileQuarantineXshiftup);
            QPushButton *pushButtonGraphsFileQuarantineXscaleup = new QPushButton();
            connect(pushButtonGraphsFileQuarantineXscaleup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileQuarantineXscaleup_clicked);
            pushButtonGraphsFileQuarantineXscaleup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileQuarantineXscaleup->setMaximumWidth(13);
            pushButtonGraphsFileQuarantineXscaleup->setIcon(QIcon(QPixmap(":/images/left.png")));
            hboxPageQuarantinedFiles->addWidget(pushButtonGraphsFileQuarantineXscaleup);
            QPushButton *pushButtonGraphsFileQuarantineXscaledown = new QPushButton();
            connect(pushButtonGraphsFileQuarantineXscaledown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileQuarantineXscaledown_clicked);
            pushButtonGraphsFileQuarantineXscaledown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileQuarantineXscaledown->setMaximumWidth(13);
            pushButtonGraphsFileQuarantineXscaledown->setIcon(QIcon(QPixmap(":/images/right.png")));
            hboxPageQuarantinedFiles->addWidget(pushButtonGraphsFileQuarantineXscaledown);
            QPushButton *pushButtonGraphsFileQuarantineXshiftdown = new QPushButton();
            connect(pushButtonGraphsFileQuarantineXshiftdown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsFileQuarantineXshiftdown_clicked);
            pushButtonGraphsFileQuarantineXshiftdown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsFileQuarantineXshiftdown->setMaximumWidth(26);
            pushButtonGraphsFileQuarantineXshiftdown->setIcon(QIcon(QPixmap(":/images/rightright.png")));
            hboxPageQuarantinedFiles->addWidget(pushButtonGraphsFileQuarantineXshiftdown);
        }

        {
            QWidget *pageSnortEvents = new QWidget();
            stackedWidgetGraphs->addWidget(pageSnortEvents);
            QVBoxLayout *vboxPageSnortEvents = new QVBoxLayout();
            pageSnortEvents->setLayout(vboxPageSnortEvents);

            chartviewSnortEvents = new QChartView();
            chartviewSnortEvents->setRenderHint(QPainter::Antialiasing);
            chartviewSnortEvents->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            vboxPageSnortEvents->addWidget(chartviewSnortEvents);

            QHBoxLayout *hboxPageSnortEvents = new QHBoxLayout();
            vboxPageSnortEvents->addLayout(hboxPageSnortEvents);
            hboxPageSnortEvents->addStretch();
            labelGraphsSnortEventsXYPosition1 = new QLabel("1");
            hboxPageSnortEvents->addWidget(labelGraphsSnortEventsXYPosition1);
            hboxPageSnortEvents->addStretch();
            labelGraphsSnortEventsXYPosition2 = new QLabel("2");
            hboxPageSnortEvents->addWidget(labelGraphsSnortEventsXYPosition2);
            hboxPageSnortEvents->addStretch();
            QPushButton *pushButtonGraphsSnortEventsResetGraph = new QPushButton();
            connect(pushButtonGraphsSnortEventsResetGraph, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsSnortEventsResetGraph_clicked);
            pushButtonGraphsSnortEventsResetGraph->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsSnortEventsResetGraph->setMaximumWidth(26);
            pushButtonGraphsSnortEventsResetGraph->setIcon(QIcon(QPixmap(":/images/reset.png")));
            hboxPageSnortEvents->addWidget(pushButtonGraphsSnortEventsResetGraph);
            QPushButton *pushButtonGraphsSnortEventsXshiftup = new QPushButton();
            connect(pushButtonGraphsSnortEventsXshiftup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsSnortEventsXshiftup_clicked);
            pushButtonGraphsSnortEventsXshiftup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsSnortEventsXshiftup->setMaximumWidth(26);
            pushButtonGraphsSnortEventsXshiftup->setIcon(QIcon(QPixmap(":/images/leftleft.png")));
            hboxPageSnortEvents->addWidget(pushButtonGraphsSnortEventsXshiftup);
            QPushButton *pushButtonGraphsSnortEventsXscaleup = new QPushButton();
            connect(pushButtonGraphsSnortEventsXscaleup, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsSnortEventsXscaleup_clicked);
            pushButtonGraphsSnortEventsXscaleup->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsSnortEventsXscaleup->setMaximumWidth(13);
            pushButtonGraphsSnortEventsXscaleup->setIcon(QIcon(QPixmap(":/images/left.png")));
            hboxPageSnortEvents->addWidget(pushButtonGraphsSnortEventsXscaleup);
            QPushButton *pushButtonGraphsSnortEventsXscaledown = new QPushButton();
            connect(pushButtonGraphsSnortEventsXscaledown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsSnortEventsXscaledown_clicked);
            pushButtonGraphsSnortEventsXscaledown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsSnortEventsXscaledown->setMaximumWidth(13);
            pushButtonGraphsSnortEventsXscaledown->setIcon(QIcon(QPixmap(":/images/right.png")));
            hboxPageSnortEvents->addWidget(pushButtonGraphsSnortEventsXscaledown);
            QPushButton *pushButtonGraphsSnortEventsXshiftdown = new QPushButton();
            connect(pushButtonGraphsSnortEventsXshiftdown, &QPushButton::clicked, this, &MainWindow::on_pushButtonGraphsSnortEventsXshiftdown_clicked);
            pushButtonGraphsSnortEventsXshiftdown->setFocusPolicy(Qt::NoFocus);
            pushButtonGraphsSnortEventsXshiftdown->setMaximumWidth(26);
            pushButtonGraphsSnortEventsXshiftdown->setIcon(QIcon(QPixmap(":/images/rightright.png")));
            hboxPageSnortEvents->addWidget(pushButtonGraphsSnortEventsXshiftdown);
        }

        stackedWidgetGraphs->setCurrentIndex(0);
        comboBoxGraphsSubTitleSelector->setCurrentIndex(0);
        connect(comboBoxGraphsSubTitleSelector, QOverload<int>::of(&QComboBox::activated), stackedWidgetGraphs, &QStackedWidget::setCurrentIndex);
    }

    QVBoxLayout *layoutStack09 = new QVBoxLayout();
    widgetStackedConfigure->setLayout(layoutStack09);
    {
        QLabel *labelSetupTitle = new QLabel("Configure");
        labelSetupTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelSetupTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelSetupTitle->setFont(fontLabel);
        layoutStack09->addWidget(labelSetupTitle);

        QFrame *frameSetup = new QFrame();
        frameSetup->setStyleSheet("background-color: #b6b6b6;");
        frameSetup->setFrameShadow(QFrame::Plain);
        frameSetup->setFrameShape(QFrame::WinPanel);
        layoutStack09->addWidget(frameSetup);
        QVBoxLayout *vboxSetup = new QVBoxLayout();
        frameSetup->setLayout(vboxSetup);

        labelSetupAccessPrefs = new QLabel("<p>Configuration settings for various ClamAV "
                                                   "related products</p><a href=\"AccessPreferences\">"
                                                   "Access preferences...</a>");
        connect(labelSetupAccessPrefs, &QLabel::linkActivated, this, &MainWindow::on_labelSetupAccessPrefs_linkActivated);
        vboxSetup->addWidget(labelSetupAccessPrefs);

        layoutStack09->addStretch();
    }

    QVBoxLayout *layoutStack10 = new QVBoxLayout();
    widgetStackedSnort->setLayout(layoutStack10);
    {
        QScrollArea *scrollAreaSnort = new QScrollArea();
        scrollAreaSnort->setStyleSheet("background-color: #ffffff;");
        scrollAreaSnort->setWidgetResizable(true);
        layoutStack10->addWidget(scrollAreaSnort);

        QWidget *scrollAreaWidgetSnortContents = new QWidget();
        scrollAreaSnort->setWidget(scrollAreaWidgetSnortContents);

        QVBoxLayout *vboxScrollAreaWidgetSnortContents = new QVBoxLayout();
        scrollAreaWidgetSnortContents->setLayout(vboxScrollAreaWidgetSnortContents);

        QLabel *labelSnortTitle = new QLabel("Snort");
        labelSnortTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelSnortTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelSnortTitle->setFont(fontLabel);
        vboxScrollAreaWidgetSnortContents->addWidget(labelSnortTitle);

        QFrame *frameSnort = new QFrame();
        frameSnort->setStyleSheet("background-color: #b6b6b6;");
        frameSnort->setFrameShadow(QFrame::Plain);
        frameSnort->setFrameShape(QFrame::WinPanel);
        vboxScrollAreaWidgetSnortContents->addWidget(frameSnort);
        QVBoxLayout *vboxSnort = new QVBoxLayout();
        frameSnort->setLayout(vboxSnort);

        QHBoxLayout *hboxSnort1 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort1);
        QLabel *labelSnortLocalVersionName = new QLabel("Local Snort Version: ");
        hboxSnort1->addWidget(labelSnortLocalVersionName);
        hboxSnort1->addStretch();
        labelSnortLocalVersionVal = new QLabel();
        hboxSnort1->addWidget(labelSnortLocalVersionVal);

        QHBoxLayout *hboxSnort2 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort2);
        QLabel *labelSnortRemoteVersionName = new QLabel("Remote Snort Version: ");
        hboxSnort2->addWidget(labelSnortRemoteVersionName);
        hboxSnort2->addStretch();
        labelSnortRemoteVersionVal = new QLabel();
        hboxSnort2->addWidget(labelSnortRemoteVersionVal);

        QFrame *hline1 = new QFrame();
        hline1->setFrameShape(QFrame::HLine);
        vboxSnort->addWidget(hline1);

        QHBoxLayout *hboxSnort3 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort3);
        QLabel *labelSnortLocalRulesName = new QLabel("Local Snort Rules: ");
        hboxSnort3->addWidget(labelSnortLocalRulesName);
        hboxSnort3->addStretch();
        labelSnortLocalRulesVal = new QLabel();
        hboxSnort3->addWidget(labelSnortLocalRulesVal);

        QHBoxLayout *hboxSnort4 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort4);
        QLabel *labelSnortRemoteRulesName = new QLabel("Remote Snort Rules: ");
        hboxSnort4->addWidget(labelSnortRemoteRulesName);
        hboxSnort4->addStretch();
        labelSnortRemoteRulesVal = new QLabel();
        hboxSnort4->addWidget(labelSnortRemoteRulesVal);

        QFrame *hline2 = new QFrame();
        hline2->setFrameShape(QFrame::HLine);
        vboxSnort->addWidget(hline2);

        QHBoxLayout *hboxSnort5 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort5);
        labelSnortExtraInfo = new QLabel();
        labelSnortExtraInfo->setWordWrap(true);
        hboxSnort5->addWidget(labelSnortExtraInfo);
        hboxSnort5->addStretch();

        QHBoxLayout *hboxSnort6 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort6);
        labelSnortExtraInfo2 = new QLabel();
        labelSnortExtraInfo2->setWordWrap(true);
        hboxSnort6->addWidget(labelSnortExtraInfo2);
        hboxSnort6->addStretch();

        QHBoxLayout *hboxSnort7 = new QHBoxLayout();
        vboxSnort->addLayout(hboxSnort7);
        labelSnortExtraInfo3 = new QLabel();
        labelSnortExtraInfo3->setWordWrap(true);
        hboxSnort7->addWidget(labelSnortExtraInfo3);
        hboxSnort7->addStretch();

        vboxScrollAreaWidgetSnortContents->addStretch();
    }

    QVBoxLayout *layoutStack11 = new QVBoxLayout();
    widgetStackedHelp->setLayout(layoutStack11);
    {
        QScrollArea *scrollArea = new QScrollArea();
        scrollArea->setStyleSheet("background-color: #ffffff;");
        scrollArea->setWidgetResizable(true);
        layoutStack11->addWidget(scrollArea);

        QWidget *scrollAreaWidgetContents = new QWidget();
        scrollArea->setWidget(scrollAreaWidgetContents);

        QVBoxLayout *vboxScrollAreaWidgetContents = new QVBoxLayout();
        scrollAreaWidgetContents->setLayout(vboxScrollAreaWidgetContents);

        QLabel *labelHelpTitle = new QLabel("Help");
        labelHelpTitle->setStyleSheet("color: #4A4A4A;");
        fontLabel = labelHelpTitle->font();
        fontLabel.setPointSize(20);
        fontLabel.setBold(true);
        labelHelpTitle->setFont(fontLabel);
        labelHelpTitle->setWordWrap(true);
        vboxScrollAreaWidgetContents->addWidget(labelHelpTitle);
        labelHelpTitleSubtitle = new QLabel("<html><head/><body><p><span style=\" font-weight:600;\">"
            "Clam One - </span>"
            "<span style=\" font-weight:600; text-decoration: underline;\"><a href=\"clicked_about\">About</a></span> - "
            "<span style=\" font-weight:600; text-decoration: underline;\"><a href=\"clicked_home\">Home</a></span> - "
            "<span style=\" font-weight:600; text-decoration: underline;\"><a href=\"clicked_scanning\">Scanning</a></span> - "
            "<span style=\" font-weight:600; text-decoration: underline;\"><a href=\"clicked_schedule\">Schedule</a></span>"
            "</p></body></html>");
        connect(labelHelpTitleSubtitle, &QLabel::linkActivated, this, &MainWindow::on_labelHelpTitleSubtitle_linkActivated);
        labelHelpTitleSubtitle->setWordWrap(true);
        vboxScrollAreaWidgetContents->addWidget(labelHelpTitleSubtitle);
        labelHelpMain = new QLabel();
        setLabelHelpMainHome();
        labelHelpMain->setWordWrap(true);
        labelHelpMain->setOpenExternalLinks(true);
        labelHelpMain->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::LinksAccessibleByMouse | Qt::LinksAccessibleByKeyboard);
        vboxScrollAreaWidgetContents->addWidget(labelHelpMain);
        vboxScrollAreaWidgetContents->addStretch();
    }

    connect(listWidget, &QListWidget::currentRowChanged, stackedWidget, &QStackedWidget::setCurrentIndex);
    listWidget->setCurrentRow(0);
}

void MainWindow::setLabelHelpMainHome(){
    labelHelpMain->setText("<html><head/><body><p><br/>This program is desktop frontend "
                           "application for the popular clamav antivirus engine. The design "
                           "features of this application allow you to quickly navagative "
                           "the complex configuration’s of clamav’s design and customize "
                           "them to your desire, monitor ther status of the detection engine, "
                           "perform custom virus scans, maintains an individual log of detection "
                           "and prevention events, quarintines and locks potential threats, and "
                           "personally alerts you when it detects a problem. </p><p>Source code "
                           "can be located at <a href=\"https://github.com/ClamOne/ClamOne\"><span "
                           "style=\" text-decoration: underline; color:#0000ff;\">"
                           "https://github.com/ClamOne/ClamOne</span></a> and inquiries sent to "
                           "<a href=\"mailto:clamavone@protonmail.com\"><span style=\" text-decoration: "
                           "underline; color:#0000ff;\">clamavone@protonmail.com</span></a>."
                           "</p><p>Documentation is currently lacking, but will be added to the "
                           "source code webpage in due time.</p><p>If you care to donate to this "
                           "project:</p><p>BTC: <a href=\"https://clamone.github.io/\"><span "
                           "style=\" text-decoration: underline; color:#0000ff;\">"
                           "https://clamone.github.io/</span></a><br/></p></body></html>");
}

void MainWindow::setLabelHelpMainScanning(){
    labelHelpMain->setText("<html><head/>"
        "<body style=\"max-width:8.5in;margin-top:0.7874in; margin-bottom:0.7874in; margin-left:0.7874in; margin-right:0.7874in; \">"
        "<p><span>The \"Scanning\" section provides the ability to manually scan single files, multiple files, directorys, or any "
        "combination of the lot. </span></p><p></p><p>The Quick scan allows a more detailed selection of the files one would "
        "like to scan.</p><p> </p><p>The Deep scan has a set of predefined directories which encompass most normally readable "
        "directories.</p></body></html>");
}

void MainWindow::setLabelHelpMainSchedule(){
    labelHelpMain->setText("<html></head>"
    "<body style=\"max-width:8.5in;margin-top:0.7874in; margin-bottom:0.7874in; margin-left:0.7874in; margin-right:0.7874in; \">"
    "<p><span>The \"</span><span>Schedule</span><span>\" section provides the ability to </span><span>plan for a reocurring scan to "
    "take place in the future</span><span>. </span></p><p> </p><p> </p></body></html>");
}

void MainWindow::iconActivated(QSystemTrayIcon::ActivationReason reason){
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        if(isVisible()){
            allHide();
        }else{
            allShow();
            listWidget->setCurrentRow(ClamOneMainStackOrder::Scan);
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
    int rClamd = -1, rFresh = -1, rClamonacc = -1, rSnort = -1;
    QByteArray whichPkexec, whichKill;
    if(!find_file(&whichPkexec, "pkexec") || !find_file(&whichKill, "kill"))
        return;
    ckProc(&rClamd, &rFresh, &rClamonacc, &rSnort);
    if(!whichPkexec.isEmpty() && !whichKill.isEmpty() && rFresh > 0){
        QProcess::execute(QString(whichPkexec), QStringList() << QString(whichKill) << "-USR1" << QString::number(rFresh));
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
    listWidget->setCurrentRow(ClamOneMainStackOrder::Log);
    comboBoxLog->setCurrentIndex(ClamOneEventsStackOrder::EventFound);
    stackedWidgetEvents->setCurrentIndex(ClamOneEventsStackOrder::EventFound);
    updateNewEventsCount();
}

void MainWindow::on_labelHelpTitleSubtitle_linkActivated(const QString &link){
    Q_UNUSED(link)
    if(link == "clicked_about")
        aboutLaunch();
    else if(link == "clicked_home")
        setLabelHelpMainHome();
    else if(link == "clicked_scanning")
        setLabelHelpMainScanning();
    else if(link == "clicked_schedule")
        setLabelHelpMainSchedule();
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
    if(tableWidgetQuarantine->selectedItems().isEmpty())
        return;
    qint64 current_row = tableWidgetQuarantine->currentRow();
    QString fileNameToUnQuarantine = tableWidgetQuarantine->selectedItems().at(0)->text();
    QString quarantineNameToDelete = tableWidgetQuarantine->selectedItems().at(3)->text();
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
    if(!tableWidgetQuarantine->rowCount())
        return;
    if(current_row >= tableWidgetQuarantine->rowCount())
        QTimer::singleShot(250, [=]() {
            tableWidgetQuarantine->selectRow(tableWidgetQuarantine->rowCount()-1);
        });
    else
        QTimer::singleShot(250, [=]() {
            tableWidgetQuarantine->selectRow(current_row);
        });
}

void MainWindow::on_pushButtonQuarantineUnQuarantine_clicked(){
    if(tableWidgetQuarantine->selectedItems().isEmpty())
        return;
    QString path = getValDB("quarantinefilesdirectory");
    qint64 current_row = tableWidgetQuarantine->currentRow();
    QString fileNameToUnQuarantine = tableWidgetQuarantine->selectedItems().at(0)->text();
    QString quarantineNameToDelete = tableWidgetQuarantine->selectedItems().at(3)->text();
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
    if(!tableWidgetQuarantine->rowCount())
        return;
    if(current_row >= tableWidgetQuarantine->rowCount())
        QTimer::singleShot(250, [=]() {
            tableWidgetQuarantine->selectRow(tableWidgetQuarantine->rowCount()-1);
        });
    else
        QTimer::singleShot(250, [=]() {
            tableWidgetQuarantine->selectRow(current_row);
        });
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
    listWidgetSchedule->addItem(item);
    listWidgetSchedule->setItemWidget(item, widget);
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
    for(int i = 0; i < listWidgetSchedule->count(); i++){
        QListWidgetItem *item = listWidgetSchedule->item(i);
        QWidget *widget = listWidgetSchedule->itemWidget(item);
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

void MainWindow::snortGetRemoteVersions(){
    if(getValDB("enablesnort") != "yes")
        return;
    snortRVersions.clear();
    QString lastLookup = getValDB("snortremoteversionts");
    QString versionsString = getValDB("snortremoteversion");
    QStringList versionsList;
    qint64 lastLookupTs = 0;
    qint64 currentTime = (qint64)time(NULL);
    if(!QRegExp("\\d").exactMatch(lastLookup)){
        lastLookupTs = currentTime;
        setValDB("snortremoteversionts", QString::number(lastLookupTs));
    }else{
        lastLookupTs = (qint64)lastLookup.toLongLong();
    }
    if((lastLookupTs > currentTime || currentTime - lastLookupTs < 24*60*60) && !versionsString.isEmpty()){
        versionsList = versionsString.split('\n');
        snortRVersions.clear();
        foreach(QString tmp, versionsList)
            snortRVersions.append(tmp.toLocal8Bit());
        compareSnortVersions();
        return;
    }else{
        setValDB("snortremoteversionts", QString::number(currentTime));
    }
    QNetworkRequest req(QUrl("https://www.snort.org/downloads"));
    req.setRawHeader("User-Agent", "ClamOne");
    QTimer reqTimer;

    QNetworkReply *reply = manager->get(req);
    connect(reply, &QNetworkReply::finished, [=](){
        if(reply->error() == QNetworkReply::NoError && reply->attribute(QNetworkRequest::RedirectionTargetAttribute) == QVariant::Invalid){
            snortRVersions.clear();
            QRegularExpression re("^.*snort-([0-9.]+)\\.tar\\.gz.*$");
            QString data_str = QString(reply->readAll());
            data_str = data_str.remove(QRegularExpression("\\r"));
            QStringList data_list = data_str.split("\n");
            QStringList resultStringList;
            resultStringList = data_list.filter(re);
            if(resultStringList.length() > 0){
                QRegularExpressionMatch match = re.match(resultStringList.at(0));
                if(match.hasMatch()){
                    snortRVersions.append(match.captured(1).toLocal8Bit());
                }
            }
            re.setPattern("^.*snort3-([0-9.]+)\\.tar\\.gz.*$");
            resultStringList = data_list.filter(re);
            if(resultStringList.length() > 0){
                QRegularExpressionMatch match = re.match(resultStringList.at(0));
                if(match.hasMatch()){
                    snortRVersions.append(match.captured(1).toLocal8Bit());
                }
            }
        }
        QByteArray versionsArray = snortRVersions.join('\n');
        setValDB("snortremoteversion", QString(versionsArray));
        reply->deleteLater();
        compareSnortVersions();
    });
    connect(&reqTimer, &QTimer::timeout, [=](){
        manager->disconnect();
        manager->deleteLater();
    });

    reqTimer.start(10);
}

bool MainWindow::snortGetLocalVersion(){
    if(time(NULL) < (snort_local_version_last_lookup_timestamp + DELTA_TIME_PEROID))
        return compareSnortVersions();
    snort_local_version_last_lookup_timestamp = 0;
    if(getValDB("enablesnort") != "yes")
        return compareSnortVersions();
    snortLVersion.clear();
    QRegularExpression re("^.*Version ([0-9.]+) .*$");
    QByteArray snortPathLocation = "/usr/local/bin/snort";
    if(!find_file(&snortPathLocation, "snort") || snortPathLocation.isEmpty()){
        return compareSnortVersions();
    }
    QProcess snortProc;
    snortProc.start(snortPathLocation, QStringList({"--version"}));
    snortProc.waitForFinished(3000);
    if(snortProc.exitCode() == 0){
        QByteArray snortRet = snortProc.readAllStandardError();
        QStringList snortList = QString(snortRet).split('\n').filter(re);
        if(snortList.length() > 0){
            QRegularExpressionMatch match = re.match(snortList.at(0));
            if(match.hasMatch()){
                snortLVersion = match.captured(1).toLocal8Bit();
                snort_local_version_last_lookup_timestamp = time(NULL);
            }
        }
    }
    return compareSnortVersions();
}

bool MainWindow::compareSnortVersions(){
    bool isMatch = false;
    if(snortLVersion.isEmpty()){
        labelSnortLocalVersionVal->setText("Can't Find Local Snort");
        if(snortRVersions.isEmpty()){
            labelSnortRemoteVersionVal->setText("Can't Find Remote Snort");
        }else{
            labelSnortRemoteVersionVal->setText(snortRVersions.join('/'));
        }
    }else{
        if(snortRVersions.isEmpty()){
            labelSnortLocalVersionVal->setText(snortLVersion);
            labelSnortRemoteVersionVal->setText("Can't Find Remote Snort");
        }else{
            QString match;
            int n = snortRVersions.length();
            for(int i = 0; i < n; i++){
                QByteArray remote = snortRVersions.at(i);
                if(snortLVersion == remote){
                    isMatch = true;
                    remote = "<b>"+remote+"</b>";
                }
                match.append(QString(remote)+QString((i<n-1)?"/":""));
            }
            if(isMatch)
                labelSnortLocalVersionVal->setText("<b>"+snortLVersion+"</b>");
            else
                labelSnortLocalVersionVal->setText(snortLVersion);
            labelSnortRemoteVersionVal->setText(match);
        }
    }
    return isMatch;
}



bool MainWindow::snortGetLocalTimeModifiy(){
    if(time(NULL) < (snort_local_rules_last_lookup_timestamp + DELTA_TIME_PEROID))
        return compareSnortRules();

    qint64 snort_etc = snortRecurseTimestamp("/etc/snort/etc"),
            snort_preproc_rules = snortRecurseTimestamp("/etc/snort/preproc_rules"),
            snort_rules = snortRecurseTimestamp("/etc/snort/rules"),
            snort_so_rules = snortRecurseTimestamp("/etc/snort/so_rules");
    snortLRules = qMax(snort_etc, snort_preproc_rules);
    snortLRules = qMax(snort_rules, snortLRules);
    snortLRules = qMax(snort_so_rules, snortLRules);
    snort_local_version_last_lookup_timestamp = time(NULL);
    return compareSnortRules();
}

void MainWindow::snortGetRemoteTimeModifiy(){
    snortRRules = 0;
    if(getValDB("enablesnort") != "yes")
        return;
    QString tmpSnortLVersion = (QString(snortLVersion).split(".").size()==4)?QString(snortLVersion):
        ((QString(snortLVersion).split(".").size()==3)?QString(snortLVersion)+".0":"");
    quint64 version = tmpSnortLVersion.split(".").join("").toInt();
    QString oinkcode = getValDB("oinkcode");

    QRegularExpressionMatch match = QRegularExpression("^[0-9a-f]{40}$").match(oinkcode);
    if(oinkcode.isEmpty() || !match.hasMatch()){
        labelSnortExtraInfo->setText(tr("Missing Oinkcode, required to check remote version."));
        compareSnortRules();
        return;
    }else{
        labelSnortExtraInfo->setText("");
    }
    QString lastLookup = getValDB("snortremoterulests");
    QString rulesString = getValDB("snortremoterules");
    qint64 rulesNum = 0;
    qint64 lastLookupTs = 0;
    qint64 currentTime = (qint64)time(NULL);
    if(!QRegExp("^\\d+$").exactMatch(lastLookup)){
        lastLookupTs = currentTime;
        setValDB("snortremoterulests", QString::number(lastLookupTs));
    }else{
        lastLookupTs = (qint64)lastLookup.toLongLong();
    }

    if(!QRegExp("^\\d+$").exactMatch(rulesString)){
        setValDB("snortremoterules", "0");
    }else{
        rulesNum = rulesString.toLongLong();
    }

    if((lastLookupTs > currentTime || currentTime - lastLookupTs < 24*60*60) && rulesNum){
        snortRRules = rulesNum;
        compareSnortRules();
        return;
    }else{
        setValDB("snortremoterulests", QString::number(currentTime));
    }

    QNetworkRequest req(QUrl(QStringLiteral("https://snort.org/rules/snortrules-snapshot-%1.tar.gz?oinkcode=%2").arg(version).arg(oinkcode)));
    req.setRawHeader("User-Agent", "ClamOne");

    QNetworkReply *reply = manager->get(req);
    QObject::connect(reply,  &QNetworkReply::finished, [=](){
qDebug() << "QObject::connect(reply,  &QNetworkReply::finished: " << reply->rawHeaderList();
        if(reply->header(QNetworkRequest::LocationHeader).isValid()){
            QNetworkRequest req2(reply->header(QNetworkRequest::LocationHeader).toUrl());
            req2.setRawHeader("User-Agent", "ClamOne");
            QNetworkReply *reply2 = manager->get(req2);
            QObject::connect(reply2,  &QNetworkReply::metaDataChanged, [=](){
qDebug() << "QObject::connect(reply2,  &QNetworkReply::metaDataChanged: " << reply2->rawHeaderList();
                if(reply2->header(QNetworkRequest::LastModifiedHeader).isValid()){
                    snortRRules = reply2->header(QNetworkRequest::LastModifiedHeader).toDateTime().toSecsSinceEpoch();
                    if(snortRRules){
                        setValDB("snortremoterulests", QString::number(currentTime));
                        setValDB("snortremoterules", QString::number(snortRRules));
qDebug() << "Remote Rules: " << snortRRules;
                    }
                }
                compareSnortRules();
                reply2->deleteLater();
            });
        }
        reply->deleteLater();
    });
}

bool MainWindow::compareSnortRules(){
    QString hexastr1 = QString::number(((snortLRules & 0xFF000000)>>24));
    QString hexastr2 = QString::number(((snortLRules & 0xFF0000)>>16));
    QString hexastr3 = QString::number(((snortLRules & 0xFF00)>>8));
    QString hexastr4 = QString::number((snortLRules & 0xFF));
    QString hexbstr1 = QString::number(((snortRRules & 0xFF000000)>>24));
    QString hexbstr2 = QString::number(((snortRRules & 0xFF0000)>>16));
    QString hexbstr3 = QString::number(((snortRRules & 0xFF00)>>8));
    QString hexbstr4 = QString::number((snortRRules & 0xFF));
    QString ra = QDateTime::fromMSecsSinceEpoch(((quint64)snortLRules)*1000).toString("MM/dd/yyyy hh:mm:ss AP - ")
            +hexastr1+"."+hexastr2+"."+hexastr3+"."+hexastr4;
    QString rb = QDateTime::fromMSecsSinceEpoch(((quint64)snortRRules)*1000).toString("MM/dd/yyyy hh:mm:ss AP - ")
            +hexbstr1+"."+hexbstr2+"."+hexbstr3+"."+hexbstr4;
    if(!snortLRules && !snortRRules){
        labelSnortLocalRulesVal->setText("Can't Find Local Rules");
        labelSnortRemoteRulesVal->setText("Can't Find Remote Rules");
    }else if(snortLRules && !snortRRules){
        labelSnortLocalRulesVal->setText(ra);
        labelSnortRemoteRulesVal->setText("Can't Find Remote Rules");
    }else if(!snortLRules && snortRRules){
        labelSnortLocalRulesVal->setText("Can't Find Local Rules");
        labelSnortRemoteRulesVal->setText(rb);
    }else if(snortLRules == snortRRules){
        labelSnortLocalRulesVal->setText("<b>"+ra+"</b>");
        labelSnortRemoteRulesVal->setText("<b>"+rb+"</b>");
        return true;
    }else{
        labelSnortLocalRulesVal->setText(ra);
        labelSnortRemoteRulesVal->setText(rb);
    }
    return false;
}


qint64 MainWindow::snortRecurseTimestamp(const QString path, qint64 ts){
    QFileInfo initialPath(path);
    if(initialPath.isSymLink()){
        return ts;
    }else if(initialPath.isFile()){
        QDateTime dt;
        dt.setTimeSpec(Qt::UTC);
        dt.setSecsSinceEpoch(initialPath.lastModified().toSecsSinceEpoch());
        return qMax(dt.toSecsSinceEpoch(), ts);
    }else if(initialPath.isDir()){
        qint64 localTs = ts;

        QFileInfoList files = QDir(initialPath.absoluteFilePath(), "", QDir::NoSort, QDir::Files|QDir::NoDotAndDotDot|QDir::NoSymLinks)
                .entryInfoList(QStringList() << "*.rules" << "*.c" << "*.h" << "*.conf" << "*.config" << "*.map");

        foreach(QFileInfo tmp, files)
            localTs = snortRecurseTimestamp(tmp.absoluteFilePath(), localTs);

        QFileInfoList dirs = QDir(initialPath.absoluteFilePath(), "", QDir::NoSort, QDir::Dirs|QDir::NoDotAndDotDot|QDir::NoSymLinks).entryInfoList();
        foreach(QFileInfo tmp, dirs)
            localTs = qMax(snortRecurseTimestamp(tmp.absoluteFilePath()), localTs);

        return localTs;
    }else{
        return 0;
    }
}


void MainWindow::removeScheduleItemAt(const QString link){
    int list_count = listWidgetSchedule->count();
    bool ok;
    qlonglong remove = link.toLongLong(&ok, 16);
    if(!ok || !list_count)
        return;
    for(int i = 0; i < listWidgetSchedule->count(); i++){
        if(listWidgetSchedule->item(i) == (QListWidgetItem *)remove){
            int row_num = listWidgetSchedule->row((QListWidgetItem *)remove);
            listWidgetSchedule->takeItem(row_num);
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

void MainWindow::on_pushButtonGraphsSnortEventsXscaleup_clicked(){
    graphs_snortevents_xscale++;
    if(graphs_snortevents_xscale>0xff)
        graphs_snortevents_xscale=0xff;
    initializeDateTimeLineGraphWidget(4);
}

void MainWindow::on_pushButtonGraphsSnortEventsXscaledown_clicked(){
    graphs_snortevents_xscale--;
    if(graphs_snortevents_xscale<-0xff)
        graphs_snortevents_xscale=-0xff;
    initializeDateTimeLineGraphWidget(4);
}

void MainWindow::on_pushButtonGraphsSnortEventsXshiftup_clicked(){
    graphs_snortevents_xshift += DELTA_BASE * pow(2., graphs_snortevents_xscale);
    initializeDateTimeLineGraphWidget(4);
}

void MainWindow::on_pushButtonGraphsSnortEventsXshiftdown_clicked(){
    graphs_snortevents_xshift -= DELTA_BASE * pow(2., graphs_snortevents_xscale);
    if(graphs_snortevents_xshift<0)
        graphs_snortevents_xshift=0.0;
    initializeDateTimeLineGraphWidget(4);
}

void MainWindow::on_pushButtonGraphsSnortEventsResetGraph_clicked(){
    graphs_snortevents_xscale=0;
    graphs_snortevents_xshift=0.0;
    initializeDateTimeLineGraphWidget(4);
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
    if(!tableWidgetEventQuarantined->isEnabled())
        return;
    if(intEventQuarantinedPageNumber>0)
        intEventQuarantinedPageNumber--;
    initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
}

void MainWindow::on_pushButtonEventQuarantinedPageForward_clicked(){
    if(!tableWidgetEventQuarantined->isEnabled())
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
    if(!tableWidgetEventQuarantined->isEnabled())
        return;
    intEventQuarantinedPageNumber = 0;
    initializeEventsQuarantinedTableWidget(intEventQuarantinedPageNumber);
}

void MainWindow::on_pushButtonEventQuarantinedPageEnd_clicked(){
    if(!tableWidgetEventQuarantined->isEnabled())
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
    //nc -lkU /path/to/var/run/clamav/clamd.ctl
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
    QString clamdconf_file_loc = getValDB("clamdconf");
    QFile file(clamdconf_file_loc);
    if(!file.exists()){
        errorMsg(clamdconf_file_loc+tr(" clamd.conf doesnt exist"));
        return QString();
    }
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        errorMsg(clamdconf_file_loc+tr(" clamd.conf is not readable"));
        return QString();
    }

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

QString MainWindow::getSnortName(){
    QByteArray ret;
    if(!find_file(&ret, "snort"))
        return "";
    return ret;
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
        QFile clamdconf(getValDB("clamdconf"));
        if (clamdconf.exists() && clamdconf.open(QIODevice::ReadOnly)){
            QTextStream clamdconfStream(&clamdconf);
            while (!clamdconfStream.atEnd()){
                QString line = clamdconfStream.readLine();
                QRegularExpression userRegex("^User\\s+(.*)$");
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
    if(time(NULL) < (cDns.last_lookup_timestamp + DELTA_TIME_PEROID))
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
        dnsSuccess = false;
        dns->deleteLater();
        QString res = getValDB("lastlookuptimestamp");
        if(res.isEmpty())
            return false;
        bool ok;
        int num = res.toInt(&ok, 10);
        if(!ok)
            return false;
        if(time(NULL) < (num + DELTA_WEEK) && num < time(NULL)){
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
        dnsSuccess = true;
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
                setValDB("dnsclamversion", tmp.at(0));
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

bool MainWindow::requestLocalClamdVersion(){
    localSocket->abort();
    localSocket->setServerName(localSocketFilename);
    localSocket->connectToServer(QLocalSocket::ReadWrite);
    if(!localSocket->waitForConnected() ||
        localSocket->write(QByteArray("VERSION", 7)) != (qint64)7 ||
        !localSocket->waitForReadyRead(250)){
        statusSetError();
        setErrorAVReason(tr("clamd failed to respond with clamd version info."));
        localSocket->abort();
        labelUpdateLocalEngineVal->setText("");
    }else{
        labelUpdateLocalEngineVal->setText(QString(localSocket->readAll()).split("/").at(0).split(" ").at(1));
    }
    return true;
}

void MainWindow::timerSlot(){
    bool isClamdError = false, isFreshclamError = false, isClamonaccError = false, isUpdateError = false, isActiveThreatDetected = false;
    bool isSnortError = false;
    int rClamd = -1, rFresh = -1, rClamonacc = -1, rSnort = -1;
    ckProc(&rClamd, &rFresh, &rClamonacc, &rSnort);

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

    //FRESHCLAM NOT RUNNING
    if(rFresh < 1){
        labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        isFreshclamError = true;
        if(!isClamdError){
            statusSetError();
            labelStatusProtectionStateDetails->setText(tr("freshclam is currently not running."));
        }
    }else{
        labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }

    //ONACCESS NOT RUNNING
    if(getValDB("monitoronaccess")=="yes" && rClamonacc < 1){
        labelStatusEnabledItem3->setText(tr("OnAccess"));
        labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        isClamonaccError = true;
        if(!isClamdError && !isFreshclamError){
            statusSetError();
            labelStatusProtectionStateDetails->setText(tr("OnAccess is configured in Clam One, but currently not running."));
        }
    }else if(getValDB("monitoronaccess")=="yes"){
        labelStatusEnabledItem3->setText(tr("OnAccess"));
        labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }else{
        setEnabledOnAccess(false);
    }

    //SNORT NOT RUNNING
    if(getValDB("enablesnort")=="yes"){
        bool snortLocalVResult = snortGetLocalVersion();
        bool snortLocalTResult = snortGetLocalTimeModifiy();
        if(rSnort < 1){
            labelStatusEnabledItem5->setText(tr("Snort Network Intrusion Detection System"));
            labelStatusEnabledItem5Icon->setPixmap(QPixmap(":/images/cross_16.png"));
            labelSnortExtraInfo2->setText("");
            labelSnortExtraInfo3->setText("");
            isSnortError = true;
            if(!isClamdError && !isFreshclamError && !isClamonaccError){
                statusSetError();
                labelStatusProtectionStateDetails->setText(tr("Snort is configured in Clam One, but currently not running."));
            }
        }else if(!snortLocalTResult && !isClamdError && !isFreshclamError && !isClamonaccError){
            labelStatusEnabledItem5->setText(tr("Snort Rules Not Up To Date"));
            labelStatusEnabledItem5Icon->setPixmap(QPixmap(":/images/cross_16.png"));
            labelSnortExtraInfo2->setText(tr("There was a problem attempting to update the snort rules to the most current form. The IDS rules database is out-of-date"));
            labelSnortExtraInfo3->setText("");
            isSnortError = true;
            if(!isClamdError && !isFreshclamError && !isClamonaccError){
                statusSetWarn();
                labelStatusProtectionStateDetails->setText(tr("Snort Rules Are Out Of Date"));
            }
        }else if(!snortLocalVResult && !isClamdError && !isFreshclamError && !isClamonaccError){
            labelStatusEnabledItem5->setText(tr("Snort Version Not Up To Date"));
            labelStatusEnabledItem5Icon->setPixmap(QPixmap(":/images/cross_16.png"));
            labelSnortExtraInfo2->setText("");
            labelSnortExtraInfo3->setText(tr("There was a problem attempting to match the system version of snort to the most current form. The Snort Executable is out-of-date"));
            isSnortError = true;
            if(!isClamdError && !isFreshclamError && !isClamonaccError){
                statusSetWarn();
                labelStatusProtectionStateDetails->setText(tr("Snort Version Is Out Of Date"));
            }
        }else{
            labelStatusEnabledItem5->setText(tr("Snort Network Intrusion Detection System"));
            labelStatusEnabledItem5Icon->setPixmap(QPixmap(":/images/check_16.png"));
            labelSnortExtraInfo2->setText("");
            labelSnortExtraInfo3->setText("");
        }
    }else{
        setEnabledSnort(false);
    }

    //CLAMAV DEFS OUTDATED
    if(!checkDefsHeaderDaily()){
        labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the daily.cld virus definition database. The file's header looks malformed."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isSnortError){
             statusSetWarn();
             labelStatusProtectionStateDetails->setText(tr("Unable To Check daily.cld"));
        }
    }
    if(!isUpdateError && !checkDefsHeaderMain()){
        labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the main.cld virus definition database. The file's header looks malformed."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isSnortError){
             statusSetWarn();
             labelStatusProtectionStateDetails->setText(tr("Unable To Check main.cld"));
        }
    }
    if(!isUpdateError && !checkDefsHeaderByte()){
        labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the bytecode.cld virus definition database. The file's header looks malformed."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isSnortError){
             statusSetWarn();
             labelStatusProtectionStateDetails->setText(tr("Unable To Check bytecode.cld"));
        }
    }
    requestUpdatedcDns();
    if(!isUpdateError && !dnsSuccess){
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/ques_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem attempting to lookup the DNS TXT current virus definition info. Check your internet connectivity."));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isSnortError){
             statusSetCaution();
             labelStatusProtectionStateDetails->setText(tr("Unable To Establish Internet Connection"));
        }
    }

    if(!isUpdateError && dnsSuccess &&
            ( cDns.daily_ver != dailyDefHeader.version ||
              cDns.main_ver != mainDefHeader.version ||
              cDns.bytecode_ver != byteDefHeader.version
            )
        ){
        labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Update Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem attempting to update the virus definition database to the most current form. The virus definition database is out-of-date"));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isSnortError){
            statusSetWarn();
            labelStatusProtectionStateDetails->setText(tr("Virus Definitions Are Out Of Date"));
        }
    }else if(!isUpdateError){
        labelStatusEnabledItem4->setText(tr("Definitions Up To Date"));
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/check_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Updated."));
        labelUpdateMessageDetails->setText(tr("The virus definition database is up-to-date<br /><br />"));
    }

    labelUpdateLocalDailyVal->setText(QDateTime::fromMSecsSinceEpoch(((quint64)dailyDefHeader.timestamp)*1000).toString("MM/dd/yyyy hh:mm:ss AP")
                                          +" d-"+QString::number(dailyDefHeader.version));
    labelUpdateLocalMainVal->setText(QDateTime::fromMSecsSinceEpoch(((quint64)mainDefHeader.timestamp)*1000).toString("MM/dd/yyyy hh:mm:ss AP")
                                         +" m-"+QString::number(mainDefHeader.version));
    labelUpdateLocalByteVal->setText(QDateTime::fromMSecsSinceEpoch(((quint64)byteDefHeader.timestamp)*1000).toString("MM/dd/yyyy hh:mm:ss AP")
                                         +" b-"+QString::number(byteDefHeader.version));

    if(dnsSuccess){
        labelUpdateRemoteVersionVal->setText(
                    "d-"+QString::number(cDns.daily_ver)+
                    ", m-"+QString::number(cDns.main_ver)+
                    ", b-"+QString::number(cDns.bytecode_ver));

        labelUpdateRemoteEngineVal->setText(QString::number(cDns.ver_major)+"."+
                                            QString::number(cDns.ver_minor)+"."+
                                            QString::number(cDns.ver_build));
    }else{
        labelUpdateRemoteVersionVal->setText("");
        labelUpdateRemoteEngineVal->setText("");
    }

    requestLocalClamdVersion();

    if(!isUpdateError && dnsSuccess && !labelUpdateRemoteEngineVal->text().isEmpty() &&
            !labelUpdateLocalEngineVal->text().isEmpty() &&
            QT_VERSION_CHECK(labelUpdateRemoteEngineVal->text().split(".").at(0).toInt(),
                             labelUpdateRemoteEngineVal->text().split(".").at(1).toInt(),
                             labelUpdateRemoteEngineVal->text().split(".").at(2).toInt())
            >
            QT_VERSION_CHECK(labelUpdateLocalEngineVal->text().split(".").at(0).toInt(),
                             labelUpdateLocalEngineVal->text().split(".").at(1).toInt(),
                             labelUpdateLocalEngineVal->text().split(".").at(2).toInt())
    ){
        labelStatusEnabledItem1->setText(tr("Clamd Engine Not Up To Date"));
        labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/ques_16.png"));
        labelUpdateMessage->setText(tr("AntiVirus Engine Update Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem matching the local Antivirus version to the most current form. The Clamd is out-of-date"));
        isUpdateError = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isSnortError){
            statusSetWarn();
            labelStatusProtectionStateDetails->setText(tr("AntiVirus Engine Is Out Of Date"));
        }
    }else{
        labelStatusEnabledItem1->setText(tr("Antivirus Engine"));
        if(!isClamdError)
            labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }

    //Update Logfile Display
    ckLogfileDisplay();

    //Check Active Threats
    QStringList existsOnFs = ckExistsOnFs();
    if(existsOnFs.length() != 0){
        isActiveThreatDetected = true;
        if(!isClamdError && !isFreshclamError && !isClamonaccError && !isUpdateError && !isSnortError){
            statusSetError();
            labelStatusProtectionStateDetails->setText(tr("Active threat detected on filesystem."));
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

    if(isClamdError || isFreshclamError || isClamonaccError || isSnortError || isUpdateError || isActiveThreatDetected)
        return;

    //NOMINAL
    statusSetOk();
}

void MainWindow::timerSlotTmp(){
    int rClamd = -1, rFresh = -1, rClamonacc = -1, rSnort = -1;
    quint8 clevel = CLAMONE_UNKNOWN;
    QString mainMessageString;
    ckProc(&rClamd, &rFresh, &rClamonacc, &rSnort);
    if(localSocketFilename.isEmpty()) localSocketFilename = getClamdLocalSocketname();

    if(rClamd < 1){
        clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        if(mainMessageString.isEmpty())
            mainMessageString = tr("clamd is currently not running.");
    }else if(localSocketFilename.isEmpty()){
        clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        if(mainMessageString.isEmpty())
            mainMessageString = tr("clamd must be configured to run locally on a \"local socket\", which is currently not enabled.");
    }else if(!clamdPingPongCk()){
        clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        if(mainMessageString.isEmpty())
            mainMessageString = tr("clamd failed to ping back.");
    }else { //Clamd Ok
        labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }

    if(rFresh < 1){
        clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        if(mainMessageString.isEmpty())
            mainMessageString = tr("freshclam is currently not running.");
    }else{ //Freshclam Ok
        labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }

    if(getValDB("monitoronaccess")=="yes" && rClamonacc < 1){
        clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        if(mainMessageString.isEmpty())
            mainMessageString = tr("OnAccess is configured in Clam One, but currently not running.");
    }else if(getValDB("monitoronaccess")=="yes"){ //OnAccess Ok
        labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }else{
        setEnabledOnAccess(false);
    }

    if(getValDB("enablesnort")=="yes" && rSnort < 1){
        if(!(static_cast<char>(clevel) & CLAMONE_ERROR))
            clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem5Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        if(mainMessageString.isEmpty())
            mainMessageString = tr("Snort is configured in Clam One, but currently not running.");
    }else if(getValDB("enablesnort")=="yes"){ //Snort Ok
        labelStatusEnabledItem5Icon->setPixmap(QPixmap(":/images/check_16.png"));
    }else{
        setEnabledSnort(false);
    }

    if(!checkDefsHeaderDaily()){
        if(clevel < CLAMONE_ERROR)
            clevel |= CLAMONE_ERROR;
        labelStatusEnabledItem4->setText(tr("Definitions Not Up To Date"));
        labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/cross_16.png"));
        labelUpdateMessage->setText(tr("Virus Definitions Check Failed."));
        labelUpdateMessageDetails->setText(tr("There was a problem attempting to check the daily.cld virus definition database. The file's header looks malformed."));

    }

    if(!(clevel))
        clevel |= CLAMONE_OK;

    if(clevel & CLAMONE_ERROR){
        statusSetError();
    }else if(clevel & CLAMONE_WARN){
        statusSetWarn();
    }else if(clevel & CLAMONE_CAUTION){
        statusSetCaution();
    }else if(clevel & CLAMONE_OK){
        statusSetOk();
    }else{
        statusSetGrey();
    }
    labelStatusProtectionStateDetails->setText(mainMessageString);
}

bool MainWindow::clamdPingPongCk(){
    localSocket->abort();
    localSocket->setServerName(localSocketFilename);
    localSocket->connectToServer(QLocalSocket::ReadWrite);
    if(!localSocket->waitForConnected() ||
        localSocket->write(QByteArray("PING", 4)) != (qint64)4 ||
        !localSocket->waitForReadyRead(250) ||
        localSocket->readAll() != QByteArray("PONG\n", 5)){
        return false;
    }
    return true;
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
    for(int i = 0; i < listWidgetSchedule->count(); i++){
        bool ok1, ok2, ok3;
        int num1, num2, num3;
        QListWidgetItem *item = listWidgetSchedule->item(i);
        QWidget *widget = listWidgetSchedule->itemWidget(item);
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

void MainWindow::ckProc(int *pidClamd, int *pidFreshclam, int *pidClamonacc, int *pidSnort){
    bool ok;
    QDir procdir("/proc");

    (*pidClamd) = -1;
    (*pidFreshclam) = -1;
    (*pidClamonacc) = -1;
    (*pidSnort) = -1;

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
        }else if(freadall == QString("snort")){
            if(pidClamonacc != Q_NULLPTR)
                (*pidSnort) = num;
        }
    }
}

quint32 MainWindow::clamdscanVersion(QByteArray *clamdscan_ver){
    QByteArray whichClamdscanRet;
    if(!find_file(&whichClamdscanRet, "clamdscan"))
        return 0xFFFFFFFF;

    QProcess clamdscanProc;
    clamdscanProc.start(whichClamdscanRet, QStringList({"--version"}));
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
void MainWindow::countTotalScanItems(const QStringList items, quint64 *count){
    foreach(QString item, items)
        (*count) += countScanItem(item);
}

quint64 MainWindow::countScanItem(const QString item){
    QFileInfo initialPath(item);
    if(initialPath.isSymLink()){
        return 0;
    }else if(initialPath.isFile()){
        return 1;
    }else if(initialPath.isDir()){
        quint64 count = QDir(initialPath.absoluteFilePath(), "", QDir::NoSort, QDir::Files|QDir::NoDotAndDotDot|QDir::NoSymLinks).count();
        QFileInfoList dirs = QDir(initialPath.absoluteFilePath(), "", QDir::NoSort, QDir::Dirs|QDir::NoDotAndDotDot|QDir::NoSymLinks).entryInfoList();
        foreach(QFileInfo tmp, dirs)
            count += countScanItem(tmp.absoluteFilePath());
        return count;
    }else{
        return 0;
    }
}

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
    labelStatusProtectionStateDetails->setText(in);
    labelStatusEnabledItem1Icon->setPixmap(QPixmap(":/images/cross_16.png"));
    labelStatusEnabledItem2Icon->setPixmap(QPixmap(":/images/ques_16.png"));
    labelStatusEnabledItem3Icon->setPixmap(QPixmap(":/images/ques_16.png"));
    labelStatusEnabledItem4Icon->setPixmap(QPixmap(":/images/ques_16.png"));
}

void MainWindow::statusSetError(){
    QIcon icon = QIcon(":/images/main_icon_red.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_red.png"));

    frameStatus->setStyleSheet("background-color: #fbc2c1;");

    labelTL->setStyleSheet("background-color: #ec1a1a;");
    labelTM->setStyleSheet("background-color: #ec1a1a;");
    labelTR->setStyleSheet("background-color: #ec1a1a;");

    labelStatusProtectionState->setText(tr("Error"));
    //labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::statusSetWarn(){
    QIcon icon = QIcon(":/images/main_icon_yellow.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_yellow.png"));

    frameStatus->setStyleSheet("background-color: #fef2d1;");

    labelTL->setStyleSheet("background-color: #eaec1a;");
    labelTM->setStyleSheet("background-color: #eaec1a;");
    labelTR->setStyleSheet("background-color: #eaec1a;");

    labelStatusProtectionState->setText(tr("Warning"));
    //labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::statusSetCaution(){
    QIcon icon = QIcon(":/images/main_icon_orange.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_orange.png"));

    frameStatus->setStyleSheet("background-color: #fef2d1;");

    labelTL->setStyleSheet("background-color: #ec811a;");
    labelTM->setStyleSheet("background-color: #ec811a;");
    labelTR->setStyleSheet("background-color: #ec811a;");

    labelStatusProtectionState->setText(tr("Caution"));
}


void MainWindow::statusSetOk(){
    QIcon icon = QIcon(":/images/main_icon_green.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_green.png"));

    frameStatus->setStyleSheet("background-color: #cbfbd1;");

    labelTL->setStyleSheet("background-color: #12bf12;");
    labelTM->setStyleSheet("background-color: #12bf12;");
    labelTR->setStyleSheet("background-color: #12bf12;");

    labelStatusProtectionState->setText(tr("All Systems Nominal"));
    labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::statusSetGrey(){
    QIcon icon = QIcon(":/images/main_icon_grey.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);
    trayIcon->show();

    listWidget->item(ClamOneMainStackOrder::Status)->setIcon(QIcon(":/images/icon_status_grey.png"));

    frameStatus->setStyleSheet("background-color: #b6b6b6;");

    labelTL->setStyleSheet("background-color: #999999;");
    labelTM->setStyleSheet("background-color: #999999;");
    labelTR->setStyleSheet("background-color: #999999;");

    labelStatusProtectionState->setText(tr("System Unknown"));
    labelStatusProtectionStateDetails->setText(tr(""));
}

void MainWindow::updateSetError(){
    frameUpdate->setStyleSheet("background-color: #fbc2c2;");
}

void MainWindow::updateSetWarn(){
    frameUpdate->setStyleSheet("background-color: #fef2d0;");
}

void MainWindow::updateSetOk(){
    frameUpdate->setStyleSheet("background-color: #cbfbd4;");
}

void MainWindow::updateSetGrey(){
    frameUpdate->setStyleSheet("background-color: #b6b6b6;");
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
          exitProgram(1);
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


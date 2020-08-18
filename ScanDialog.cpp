#include "ScanDialog.h"
#include "ScanDialog.h"
#include "ui_ScanDialog.h"

ScanDialog::ScanDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ScanDialog){
    ui->setupUi(this);
}

ScanDialog::~ScanDialog(){
    delete ui;
}

void ScanDialog::initializeQuickScan(bool active){
    if(!active){
        ui->listWidgetQuick->clear();
        ui->listWidgetDeep->clear();
        ui->plainTextEditOutput->clear();
        ui->plainTextEditOutput->setPlainText(tr(""));
        if(getClamdscanPath().isEmpty()){
            setAcceptDrops(false);
            ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Error);
            colorize(tr("111111"));
            ui->labelML->setText(tr("Scan<br />Error"));
            return;
        }
        setWindowTitle(tr("Clam One - Quick Scan"));
        setWindowIcon(QIcon(":/images/main_icon_quick_scan.png"));
        QString color = tr("7C4BD9");
        ui->labelML->setText(tr("Quick<br />Scan"));
        setAcceptDrops(true);
        ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Quick);
        colorize(color);
    }
}

void ScanDialog::initializeDeepScan(bool active){
    if(!active){
        ui->listWidgetQuick->clear();
        ui->listWidgetDeep->clear();
        setAcceptDrops(false);
        if(getClamdscanPath().isEmpty()){
            ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Error);
            colorize(tr("111111"));
            ui->labelML->setText(tr("Scan<br />Error"));
            return;
        }
        setWindowTitle(tr("Clam One - Deep Scan"));
        setWindowIcon(QIcon(":/images/main_icon_deep_scan.png")); ;
        QString color = tr("41C7D1");
        ui->labelML->setText(tr("Deep<br />Scan"));
        ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Deep);
        colorize(color);
        foreach(QFileInfo tmp, QDir("/").entryInfoList()){
            if(tmp.absoluteFilePath() != tr("/") &&
                    tmp.absoluteFilePath() != tr("/..") &&
                    tmp.absoluteFilePath() != tr("/boot") &&
                    tmp.absoluteFilePath() != tr("/cdrom") &&
                    tmp.absoluteFilePath() != tr("/dev") &&
                    tmp.absoluteFilePath() != tr("/initrd.img") &&
                    tmp.absoluteFilePath() != tr("/initrd.img.old") &&
                    tmp.absoluteFilePath() != tr("/lost+found") &&
                    tmp.absoluteFilePath() != tr("/proc") &&
                    tmp.absoluteFilePath() != tr("/run") &&
                    tmp.absoluteFilePath() != tr("/srv") &&
                    tmp.absoluteFilePath() != tr("/sys") &&
                    tmp.absoluteFilePath() != tr("/vmlinuz") &&
                    tmp.absoluteFilePath() != tr("/vmlinuz.old") ){
                addNextItem(tmp.absoluteFilePath(), ClamOneScanStackOrder::Deep);
            }
        };
    }
}

void ScanDialog::colorize(QString color){
    if(!isVisible()){
        ui->labelML->setStyleSheet(tr("* {color: qlineargradient(spread:pad, x1:0 y1:0, x2:1 y2:0, stop:0 rgba(0, 0, 0, 255), stop:1 rgba(255, 255, 255, 255)); background: qlineargradient( x1:-0.5 y1:0, x2:1.5 y2:0, stop:0 #")+color+tr(", stop:1 #fff);}"));
        ui->labelTL->setStyleSheet(tr("color: #000; background-color: #")+color+tr(";"));
        ui->labelTM->setStyleSheet(tr("background-color: #")+color+tr(";"));
        ui->labelTR->setStyleSheet(tr("background-color: #")+color+tr(";"));
        ui->labelBL->setStyleSheet(tr("color: #000; background-color: #")+color+tr(";"));
        ui->labelBM->setStyleSheet(tr("background-color: #")+color+tr(";"));
        ui->labelBR->setStyleSheet(tr("background-color: #")+color+tr(";"));
        show();
    }
}

void ScanDialog::defaultClose(){
    ui->listWidgetQuick->clear();
    ui->listWidgetDeep->clear();
    hide();
}

QStringList ScanDialog::quickListWidgetToStringList(){
    int n = ui->listWidgetQuick->count();
    QStringList qsl;
    for(int i = 0; i < n; i++){
        QString str = qobject_cast<QLabel *>(ui->listWidgetQuick->itemWidget(ui->listWidgetQuick->item(i))->layout()->itemAt(3)->widget())->text();
        qsl.append(str);
    }
    return qsl;
}

QStringList ScanDialog::deepListWidgetToStringList(){
    int n = ui->listWidgetDeep->count();
    QStringList qsl;
    for(int i = 0; i < n; i++){
        QString str = qobject_cast<QLabel *>(ui->listWidgetDeep->itemWidget(ui->listWidgetDeep->item(i))->layout()->itemAt(3)->widget())->text();
        qsl.append(str);
    }
    return qsl;
}

QString ScanDialog::getClamdscanPath(){
    QProcess *proc = new QProcess();
    proc->setProcessChannelMode(QProcess::MergedChannels);
    proc->start("which", QStringList() << "clamdscan");
    proc->waitForFinished();
    return QString(proc->readAll()).split("\n")[0];
}

void ScanDialog::removeQuickItemAt(const QString &link){
    QStringList qsl = quickListWidgetToStringList();
    bool ok;
    int removeIndex = link.toInt(&ok, 10);
    if(!ok || !qsl.size() || removeIndex >= qsl.size() || removeIndex < 0)
        return;
    qsl.removeAt(removeIndex);
    ui->listWidgetQuick->clear();
    foreach(const QString &str, qsl) {
        addNextItem(str, ClamOneScanStackOrder::Quick);
    }
}

void ScanDialog::removeDeepItemAt(const QString &link){
    QStringList qsl = deepListWidgetToStringList();
    bool ok;
    int removeIndex = link.toInt(&ok, 10);
    if(!ok || !qsl.size() || removeIndex >= qsl.size() || removeIndex < 0)
        return;
    qsl.removeAt(removeIndex);
    ui->listWidgetDeep->clear();
    foreach(const QString &str, qsl) {
        addNextItem(str, ClamOneScanStackOrder::Deep);
    }
}

void ScanDialog::addNextItem(const QString &name, ClamOneScanStackOrder type){

    if(type == ClamOneScanStackOrder::Quick && quickListWidgetToStringList().contains(name))
        return;
    if(type == ClamOneScanStackOrder::Deep && deepListWidgetToStringList().contains(name))
        return;
    QFileInfo qfi(name);
    if(!qfi.exists() || (!qfi.isFile() && !qfi.isDir() && !qfi.isSymLink()))
        return;
    if(type == ClamOneScanStackOrder::Quick && qfi.isSymLink() && quickListWidgetToStringList().contains(qfi.symLinkTarget()))
        return;
    if(type == ClamOneScanStackOrder::Deep && qfi.isSymLink() && deepListWidgetToStringList().contains(qfi.symLinkTarget()))
        return;
    QListWidgetItem *item = new QListWidgetItem();
    QWidget *widget = new QWidget();
    QHBoxLayout *layout = new QHBoxLayout();
    int n = -1;
    if(type == ClamOneScanStackOrder::Quick)
        n = ui->listWidgetQuick->count();
    if(type == ClamOneScanStackOrder::Deep)
        n = ui->listWidgetDeep->count();
    QLabel *labelDelete = new QLabel("<a href=\""+QString::number(n)+"\">X</a>");
    QLabel *labelShortName = new QLabel();
    QLabel *labelName = new QLabel();
    QLabel *labelNameHidden = new QLabel();
    if(qfi.isSymLink()){
        labelDelete->setStyleSheet("background-color: #EDD400;");
        labelShortName->setStyleSheet("background-color: #EDD400;");
    }else if(qfi.isDir()){
        labelDelete->setStyleSheet("background-color: #8F5902;");
        labelShortName->setStyleSheet("background-color: #8F5902;");
    }else if(qfi.isFile()){
        labelDelete->setStyleSheet("background-color: #4E9A06;");
        labelShortName->setStyleSheet("background-color: #4E9A06;");
    }
    labelNameHidden->setVisible(false);

    labelDelete->setAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    labelDelete->setMaximumWidth(20);
    labelDelete->setMinimumWidth(20);

    labelShortName->setText(tr("   ")+qfi.fileName()+tr("   "));

    labelName->setText(name);
    labelName->setAlignment(Qt::AlignLeft|Qt::AlignVCenter);
    labelName->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    labelNameHidden->setText(qfi.isSymLink()?qfi.symLinkTarget():qfi.absoluteFilePath());

    widget->setLayout(layout);
    layout->addWidget(labelDelete);
    layout->addWidget(labelShortName);
    layout->addWidget(labelName);
    layout->addWidget(labelNameHidden);

    item->setSizeHint(QSize(800, 30));

    if(type == ClamOneScanStackOrder::Quick){
        connect(labelDelete, &QLabel::linkActivated, this, &ScanDialog::removeQuickItemAt);
        ui->listWidgetQuick->addItem(item);
        ui->listWidgetQuick->setItemWidget(item,widget);
    }else if(type == ClamOneScanStackOrder::Deep){
        connect(labelDelete, &QLabel::linkActivated, this, &ScanDialog::removeDeepItemAt);
        ui->listWidgetDeep->addItem(item);
        ui->listWidgetDeep->setItemWidget(item,widget);
    }
}

void ScanDialog::on_pushButtonErrorClose_clicked(){
    emit setScanActive(false);
    defaultClose();
}

void ScanDialog::on_pushButtonQuickClose_clicked(){
    emit setScanActive(false);
    defaultClose();
}

void ScanDialog::on_pushButtonQuickScan_clicked(){
    emit setScanActive(true);
    ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Running);
    ui->plainTextEditOutput->clear();
    ui->plainTextEditOutput->setPlainText(tr(""));
    if(quickListWidgetToStringList().count()){
        emit initScanProcess(quickListWidgetToStringList());
    }else{
        ui->plainTextEditOutput->setPlainText(tr("No Items to Scan."));
    }
}

void ScanDialog::processReadyRead(QByteArray buffer){
    bool isAtBottom = (ui->plainTextEditOutput->verticalScrollBar()->maximum() ==
                       ui->plainTextEditOutput->verticalScrollBar()->value());
    QList<QByteArray> split = buffer.split('\n');
    foreach(QByteArray qba, split){
        QRegularExpression re;
        QRegularExpressionMatch reMatch;
        re.setPattern("^$");
        reMatch = re.match(QString(qba));
        if(reMatch.hasMatch()){
            continue;
        }
        re.setPattern("^.*: Access denied. ERROR$");
        reMatch = re.match(QString(qba));
        if(reMatch.hasMatch()){
            continue;
        }
        re.setPattern("^----------- SCAN SUMMARY -----------$");
        reMatch = re.match(QString(qba));
        if(reMatch.hasMatch()){
            qba = QByteArray("\n\n----------- SCAN SUMMARY -----------\n");
        }

        ui->plainTextEditOutput->appendPlainText(QString(qba));
    }

    if(isAtBottom)
        ui->plainTextEditOutput->verticalScrollBar()->setValue(ui->plainTextEditOutput->verticalScrollBar()->maximum());
    emit parseClamdscanLine(buffer);
    ui->listWidgetQuick->clear();
    ui->listWidgetDeep->clear();
}

void ScanDialog::processFinished(){
    bool isAtBottom = (ui->plainTextEditOutput->verticalScrollBar()->maximum() ==
                       ui->plainTextEditOutput->verticalScrollBar()->value());
    ui->plainTextEditOutput->appendPlainText("Finished.");
    if(isAtBottom)
        ui->plainTextEditOutput->verticalScrollBar()->setValue(ui->plainTextEditOutput->verticalScrollBar()->maximum());
    ui->listWidgetQuick->clear();
    ui->listWidgetDeep->clear();
    if(ui->labelRunningBusyGif->movie() && ui->labelRunningBusyGif->movie()->state() != QMovie::NotRunning)
        ui->labelRunningBusyGif->movie()->stop();
    ui->labelRunningBusyGif->setPixmap(QPixmap(""));
}

void ScanDialog::initializeFreelanceScan(bool active, QStringList stringlist){
    if(!active){
        setWindowTitle(tr("Clam One - Scheduled Scan"));
        setWindowIcon(QIcon(":/images/main_icon_quick_scan.png"));
        QString color = tr("7C4BD9");
        ui->labelML->setText(tr("Free<br />Scan"));
        colorize(color);

        emit setScanActive(true);
        ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Running);
        ui->plainTextEditOutput->clear();
        ui->plainTextEditOutput->setPlainText(tr(""));
        if(stringlist.count())
            emit initScanProcess(stringlist);
        else
            ui->plainTextEditOutput->setPlainText(tr("No Items to Scan."));
    }
}

void ScanDialog::on_pushButtonDeepClose_clicked(){
    emit setScanActive(false);
    defaultClose();
}

void ScanDialog::on_pushButtonDeepScan_clicked(){
    emit setScanActive(true);
    ui->stackedWidget->setCurrentIndex(ClamOneScanStackOrder::Running);

    QMovie *movie = new QMovie(":/images/busy.gif");
    ui->labelRunningBusyGif->setMovie(movie);
    movie->start();

    ui->plainTextEditOutput->clear();
    ui->plainTextEditOutput->setPlainText(tr(""));
    if(deepListWidgetToStringList().count()){
        emit initScanProcess(deepListWidgetToStringList());
    }else{
        ui->plainTextEditOutput->setPlainText(tr("No Items to Scan."));
    }

}

void ScanDialog::on_pushButtonAddFiles_clicked(){
    QStringList fileNames = QFileDialog::getOpenFileNames(this, tr("Open File(s) to Scan"));
    foreach (const QString &str, fileNames){
        addNextItem(str, ClamOneScanStackOrder::Quick);
    }
}

void ScanDialog::on_pushButtonAddDir_clicked(){
    QString dirName = QFileDialog::getExistingDirectory(this, tr("Open Directory to Scan"));
    addNextItem(dirName, ClamOneScanStackOrder::Quick);
}

void ScanDialog::on_pushButtonRunningAbort_clicked(){
    emit setScanActive(false);
    if(ui->labelRunningBusyGif->movie() && ui->labelRunningBusyGif->movie()->state() != QMovie::NotRunning)
        ui->labelRunningBusyGif->movie()->stop();
    ui->labelRunningBusyGif->setPixmap(QPixmap(""));
}

void ScanDialog::on_pushButtonRunningClose_clicked(){
    emit setScanActive(false);
    on_pushButtonRunningAbort_clicked();
    close();
}

void ScanDialog::dragEnterEvent(QDragEnterEvent *e){
    if(ui->stackedWidget->currentIndex() == ClamOneScanStackOrder::Quick && e->mimeData()->hasUrls()){
        e->acceptProposedAction();
    }
}

void ScanDialog::dropEvent(QDropEvent *e){
    if(ui->stackedWidget->currentIndex() == ClamOneScanStackOrder::Quick){
        foreach (const QUrl &url, e->mimeData()->urls()) {
            addNextItem(url.toLocalFile(), ClamOneScanStackOrder::Quick);
        }
    }
}

void ScanDialog::closeEvent(QCloseEvent *event){
    remoteProcKill();
    event->accept();
}

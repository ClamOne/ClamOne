#include "ListerQuarantine.h"
#include "ui_ListerQuarantine.h"

ListerQuarantine::ListerQuarantine(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ListerQuarantine)
{
    ui->setupUi(this);
    setWindowTitle("Clam One - Quarantine");
}

ListerQuarantine::~ListerQuarantine()
{
    delete ui;
}

bool ListerQuarantine::remove_from_list(QByteArray *crypt_filename, QByteArray *plain_filename){
    bool doesListAlreadyContain = false;
    QPair<QByteArray, QByteArray> tmp;
    foreach(tmp, internal){
        if(tmp.second == QString(ui->listWidget->selectedItems()[0]->text())){
            doesListAlreadyContain = true;
            *crypt_filename = tmp.first;
            *plain_filename = tmp.second;
            internal.removeOne(tmp);
            ui->listWidget->takeItem(ui->listWidget->currentRow());
            break;
        }
    }
    return doesListAlreadyContain;
}

bool ListerQuarantine::exts(QByteArray crypt_filename, QByteArray plain_filename){
    return crypt_filename.isEmpty() || plain_filename.isEmpty() ||
            !QFileInfo(plain_filename).exists() || !QFileInfo(crypt_filename).exists();
}

void ListerQuarantine::on_pushButtonYes_clicked(){
    if(!ui->listWidget->selectedItems().isEmpty()){
        QByteArray crypt_filename,  plain_filename;
        if(!remove_from_list(&crypt_filename, &plain_filename))
            return;

        if(exts(crypt_filename, plain_filename))
            return;

        if(QFile::remove(plain_filename))
            emit yesClicked();

        if(ui->listWidget->selectedItems().isEmpty())
            hide();
    }
}

void ListerQuarantine::on_pushButtonNo_clicked(){
    if(!ui->listWidget->selectedItems().isEmpty()){
        QByteArray crypt_filename,  plain_filename;
        if(!remove_from_list(&crypt_filename, &plain_filename))
            return;

        if(exts(crypt_filename, plain_filename))
            return;

        if(QFile::remove(crypt_filename))
            emit noClicked();

        if(ui->listWidget->selectedItems().isEmpty())
            hide();
    }
}

void ListerQuarantine::add_file(QByteArray crypt_filename, QByteArray plain_filename){
    show();
    bool doesListAlreadyContain = false;
    bool isListEmpty = ui->listWidget->selectedItems().isEmpty();
    QPair<QByteArray, QByteArray> tmp;
    foreach(tmp, internal){
        if(tmp.second == plain_filename){
            doesListAlreadyContain = true;
            break;
        }
    }
    if(!doesListAlreadyContain){
        ui->listWidget->addItem(plain_filename);
        tmp.first = crypt_filename;
        tmp.second = plain_filename;
        internal.append(tmp);
        setWindowState( (windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
        raise();  // for MacOS
        activateWindow(); // for Windows
    }
    if(isListEmpty)
        ui->listWidget->setCurrentRow(0);
}

void ListerQuarantine::closeEvent(QCloseEvent *event){
    event->ignore();
}


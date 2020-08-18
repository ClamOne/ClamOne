#include "AboutDialog.h"
#include "ui_AboutDialog.h"

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    ui->labelVersionVal->setText(QString(CLAMONE_VERSION)+tr(" (0x")+QString::number(CLAMONE_VERSION_L, 16)+tr(")"));
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::on_pushButtonOk_clicked(){
    this->hide();
}

void AboutDialog::closeEvent(QCloseEvent *event){
    this->hide();
    event->ignore();
}

#include "FileDialogPlug.h"

FileDialogPlug::FileDialogPlug(QString name, QString tooltip, QString defaultText, QString fileTypesFilter,
                               QFileDialog::Options options)
{
    QHBoxLayout *hbox = new QHBoxLayout();
    setLayout(hbox);
    eckbox = new QCheckBox();
    hbox->addWidget(eckbox);
    lab = new QLabel(name);
    lab->setToolTip(tooltip);
    lab->setEnabled(false);
    hbox->addWidget(lab);
    hbox->addStretch();
    lineEdit = new QLineEdit();
    lineEdit->setText(defaultText);
    lineEdit->setEnabled(false);
    hbox->addWidget(lineEdit);
    pushButton = new QPushButton();
    pushButton->setMaximumWidth(30);
    pushButton->setIcon(QIcon(":/images/icon_filedialog.png"));
    pushButton->setFocusPolicy(Qt::NoFocus);
    hbox->addWidget(pushButton);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        lineEdit->setEnabled(state);
        pushButton->setEnabled(state);
    });
    connect(pushButton, &QPushButton::clicked, [=](){
        QString tmp;
        if(options & QFileDialog::ShowDirsOnly)
            tmp = QFileDialog::getExistingDirectory(this,
                tr("Select Directory"), lineEdit->text(), options);
        else
            tmp = QFileDialog::getOpenFileName(this,
                tr("Select File"), lineEdit->text(), fileTypesFilter, Q_NULLPTR, options);
        if(!tmp.isEmpty())
            lineEdit->setText(tmp);
    });
}

FileDialogPlug::~FileDialogPlug(){

}

QCheckBox *FileDialogPlug::getEckbox() const
{
    return eckbox;
}

QLabel *FileDialogPlug::getLabel() const
{
    return lab;
}

QLineEdit *FileDialogPlug::getLineEdit() const
{
    return lineEdit;
}

QByteArray FileDialogPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked()){
        ret = QByteArray(lab->text().toLocal8Bit()+" ")+lineEdit->text().toLocal8Bit()+end;
    }
    return ret;
}

bool FileDialogPlug::lineGrabber(QByteArray line) const{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    lineEdit->setText(line);
    eckbox->setChecked(true);
    return true;
}

bool FileDialogPlug::getVersion_parameter() const
{
    return version_parameter;
}

void FileDialogPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

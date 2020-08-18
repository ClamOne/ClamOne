#include "qstringlistwidget.h"

QStringListWidget::QStringListWidget(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle(tr("QStringList Widget"));

    pos = 0; size = 0;

    QVBoxLayout *buttonLayout = new QVBoxLayout;
    buttonLayout->setSpacing(0);
    pushButtonPlus = new QPushButton();
    pushButtonPlus->setMaximumWidth(24);
    pushButtonPlus->setMaximumHeight(13);
    pushButtonPlus->setText("");
    pushButtonPlus->setIcon(QIcon(QPixmap(":/images/up.png")));

    pushButtonMinus = new QPushButton();
    pushButtonMinus->setMaximumWidth(24);
    pushButtonMinus->setMaximumHeight(13);
    pushButtonMinus->setText("");
    pushButtonMinus->setIcon(QIcon(QPixmap(":/images/down.png")));

    pushButtonDelete = new QPushButton();
    pushButtonDelete->setMaximumWidth(24);
    pushButtonDelete->setMaximumHeight(24);
    pushButtonDelete->setText("");
    pushButtonDelete->setIcon(QIcon(QPixmap(":/images/delete.png")));
    labelIndictor = new QLabel(tr("0/0"));
    lineEdit = new QLineEdit();
    spinBox = new QSpinBox();
    spinBox->setMaximum(0);
    spinBox->setMinimum(0);
    lineEdit->setEnabled(false);

    buttonLayout->addWidget(pushButtonPlus);
    buttonLayout->addWidget(pushButtonMinus);

    QHBoxLayout *mainLayout = new QHBoxLayout;
    mainLayout->addLayout(buttonLayout);
    mainLayout->addWidget(pushButtonDelete);
    mainLayout->addWidget(labelIndictor);
    mainLayout->addWidget(lineEdit);
    mainLayout->addWidget(spinBox);
    setLayout(mainLayout);

    connect(pushButtonPlus, &QPushButton::clicked, this, &QStringListWidget::incSize);
    connect(pushButtonMinus, &QPushButton::clicked, this, &QStringListWidget::decSize);
    connect(spinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &QStringListWidget::changeIndex);
    connect(lineEdit, &QLineEdit::textChanged, this, &QStringListWidget::changeLineEdit);
    connect(pushButtonDelete, &QPushButton::clicked, this, &QStringListWidget::deleteButton);
}

const QStringList QStringListWidget::getQStringList(){
    return strings;
}

const QByteArray QStringListWidget::getBlob(){
    QByteArray blob;
    foreach(QString line, strings){
        blob.append(line.toLocal8Bit()+'\0');
    }
    return blob;
}

void QStringListWidget::setQStringList(const QStringList val){
    strings = val;
    if(strings.isEmpty()){
        pos = 0;
    }else{
        pos = 1;
    }
    size = strings.length();
    if(size){
        spinBox->setMaximum(size);
        spinBox->setMinimum(1);
        lineEdit->setEnabled(true);
        lineEdit->setText(strings.at(0));
    }else{
        spinBox->setMaximum(0);
        spinBox->setMinimum(0);
        lineEdit->setEnabled(false);
        lineEdit->setText(tr(""));
    }
    checkIfStringlistChanged();
    updateIndicator();
}

void QStringListWidget::checkIfStringlistChanged(){
    QByteArray hash = QCryptographicHash::hash(getBlob(), QCryptographicHash::Md5);
    if(hash != oldhash)
        emit stringlistChange();
    oldhash = hash;
}

void QStringListWidget::incSize(){
    if(size < INT_MAX){
        size++;
        spinBox->setMaximum(size);
        spinBox->setMinimum(1);
        strings.append(QString());
        lineEdit->setEnabled(true);
    }
    checkIfStringlistChanged();
    updateIndicator();
}

void QStringListWidget::decSize(){
    if(size > 0){
        size--;
        if(!strings.isEmpty())
            strings.removeLast();
        if(size){
            spinBox->setMaximum(size);
            spinBox->setMinimum(1);
            lineEdit->setEnabled(true);
        }else{
            spinBox->setMaximum(0);
            spinBox->setMinimum(0);
            lineEdit->setEnabled(false);
            lineEdit->setText(tr(""));
        }
    }
    checkIfStringlistChanged();
    updateIndicator();
    if(pos >= size){
        if(size){
            pos = size;
        }else{
            pos = 0;
        }
        spinBox->setValue(pos);
    }
}

void QStringListWidget::changeIndex(int val){
    pos = val;
    if(size && (int)pos-1 < strings.length()){
        lineEdit->setText(strings.at(pos-1));
    }
    updateIndicator();
}

void QStringListWidget::changeLineEdit(const QString val){
    if(size && (int)pos-1 < strings.length()){
        strings.replace(pos-1, val);
    }
    checkIfStringlistChanged();
}

void QStringListWidget::deleteButton(){
    if(strings.count()){
        QStringList strList = strings;
        strList.removeAt(pos-1);
        setQStringList(strList);
    }
}

void QStringListWidget::updateIndicator(){
    labelIndictor->setText(QString::number(pos)+tr("/")+QString::number(size));
}

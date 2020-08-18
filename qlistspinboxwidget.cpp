#include "qlistspinboxwidget.h"

QListSpinBoxWidget::QListSpinBoxWidget(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle(tr("QListSpinBox Widget"));

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
    labelIndictor = new QLabel(tr("0/0"));
    mainValueSpinBox = new QSpinBox();
    mainValueSpinBox->setMinimum(-0x80000000);
    mainValueSpinBox->setMaximum(0x80000000-1);
    spinBox = new QSpinBox();
    spinBox->setMaximum(0);
    spinBox->setMinimum(0);
    mainValueSpinBox->setEnabled(false);

    buttonLayout->addWidget(pushButtonPlus);
    buttonLayout->addWidget(pushButtonMinus);

    QHBoxLayout *mainLayout = new QHBoxLayout;
    mainLayout->addLayout(buttonLayout);
    mainLayout->addWidget(labelIndictor);
    mainLayout->addWidget(mainValueSpinBox);
    mainLayout->addWidget(spinBox);
    setLayout(mainLayout);

    connect(pushButtonPlus, &QPushButton::clicked, this, &QListSpinBoxWidget::incSize);
    connect(pushButtonMinus, &QPushButton::clicked, this, &QListSpinBoxWidget::decSize);
    connect(spinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &QListSpinBoxWidget::changeIndex);
    connect(mainValueSpinBox, static_cast<void(QSpinBox::*)(int)>(&QSpinBox::valueChanged), this, &QListSpinBoxWidget::changeSpinBoxValue);
}

const QList<int> QListSpinBoxWidget::getQListInt(){
    return values;
}

void QListSpinBoxWidget::setQListInt(const QList<int> val){
    values = val;
    if(values.isEmpty()){
        pos = 0;
    }else{
        pos = 1;
    }
    size = values.length();
    if(size){
        spinBox->setMaximum(size);
        spinBox->setMinimum(1);
        mainValueSpinBox->setEnabled(true);
        mainValueSpinBox->setValue(values.at(0));
    }else{
        spinBox->setMaximum(0);
        spinBox->setMinimum(0);
        mainValueSpinBox->setEnabled(false);
        mainValueSpinBox->setValue(0);
    }
    updateIndicator();
}

void QListSpinBoxWidget::incSize(){
    if(size < INT_MAX){
        size++;
        spinBox->setMaximum(size);
        spinBox->setMinimum(1);
        values.append(0);
        mainValueSpinBox->setEnabled(true);
    }
    updateIndicator();
}

void QListSpinBoxWidget::decSize(){
    if(size > 0){
        size--;
        if(!values.isEmpty())
            values.removeLast();
        if(size){
            spinBox->setMaximum(size);
            spinBox->setMinimum(1);
            mainValueSpinBox->setEnabled(true);
        }else{
            spinBox->setMaximum(0);
            spinBox->setMinimum(0);
            mainValueSpinBox->setEnabled(false);
            mainValueSpinBox->setValue(0);
        }
    }
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

void QListSpinBoxWidget::changeIndex(int val){
    pos = val;
    if(size && (int)pos-1 < values.length()){
        mainValueSpinBox->setValue(values.at(pos-1));
    }
    updateIndicator();
}

void QListSpinBoxWidget::changeSpinBoxValue(const int val){
    if(size && (int)pos-1 < values.length()){
        values.replace(pos-1, val);
    }
}

void QListSpinBoxWidget::updateIndicator(){
    labelIndictor->setText(QString::number(pos)+tr("/")+QString::number(size));
}

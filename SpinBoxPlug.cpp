#include "SpinBoxPlug.h"

SpinBoxPlug::SpinBoxPlug(QString name, QString tooltip, int min, int max, int defaultNum, int displayBase)
{
    QHBoxLayout *hbox = new QHBoxLayout();
    setLayout(hbox);
    eckbox = new QCheckBox();
    hbox->addWidget(eckbox);
    lab = new QLabel(name);
    lab->setToolTip(tooltip);
    lab->setEnabled(false);
    hbox->addWidget(lab);
    hbox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    spinBox = new QSpinBox();
    spinBox->setMinimum(min);
    spinBox->setMaximum(max);
    spinBox->setValue(defaultNum);
    spinBox->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
    spinBox->setButtonSymbols(QAbstractSpinBox::NoButtons);
    spinBox->setDisplayIntegerBase(displayBase);
    if(displayBase == 16)
        spinBox->setPrefix("0x");
    spinBox->setEnabled(false);
    hbox->addWidget(spinBox);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        spinBox->setEnabled(state);
    });
}

SpinBoxPlug::~SpinBoxPlug()
{

}

QCheckBox *SpinBoxPlug::getEckbox() const
{
    return eckbox;
}

QSpinBox *SpinBoxPlug::getSpinBox() const
{
    return spinBox;
}

QByteArray SpinBoxPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked()){
        ret = QByteArray(lab->text().toLocal8Bit()+" ")+QString::number(spinBox->value()).toLocal8Bit()+end;
    }
    return ret;
}

bool SpinBoxPlug::lineGrabber(QByteArray line) const{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    QRegularExpression re;
    re.setPattern("^"+lab->text()+"\\s+(?<varname>[a-zA-Z0-9:\\/.^$]+)\\s*$");
    if(re.match(line).hasMatch()){
        bool ok;
        int num = toClamInt(re.match(line).captured("varname"), &ok);
        if(!ok)
            return false;
        spinBox->setValue(num);
        eckbox->setChecked(true);
        return true;
    }
    return false;
}

int SpinBoxPlug::toClamInt(QString in, bool *ok) const{
    if(in[in.length()-1] == "k" || in[in.length()-1] == "K"){
        (*ok) = false;
        int base = in.mid(0, in.length()-1).toInt(ok);
        if(!(*ok))
            return -1;
        return base*1000;
    }else if(in[in.length()-1] == "m" || in[in.length()-1] == "M"){
        (*ok) = false;
        int base = in.mid(0, in.length()-1).toInt(ok);
        if(!(*ok))
            return -1;
        return base*1000000;
    }else if(in[in.length()-1] == "L"){
        (*ok) = false;
        int base = in.mid(0, in.length()-1).toInt(ok);
        if(!(*ok))
            return -1;
        return base;
    }
    (*ok) = false;
    int base = in.toInt(ok);
    if(ok)
        return base;
    return -1;
}

bool SpinBoxPlug::getVersion_parameter() const
{
    return version_parameter;
}

void SpinBoxPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

#include "CheckBoxPlug.h"

CheckBoxPlug::CheckBoxPlug(QString name, QString tooltip, bool defaultState)
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
    checkBox = new QCheckBox();
    checkBox->setEnabled(false);
    checkBox->setText(tr("no"));
    checkBox->setChecked(false);
    connect(checkBox, &QCheckBox::stateChanged, [=](int state) {
        (state)?checkBox->setText(tr("yes")):checkBox->setText(tr("no"));
    });
    checkBox->setChecked(defaultState);
    hbox->addWidget(checkBox);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        checkBox->setEnabled(state);
    });
}

CheckBoxPlug::~CheckBoxPlug(){

}

QCheckBox *CheckBoxPlug::getEckbox() const
{
    return eckbox;
}

QCheckBox *CheckBoxPlug::getCheckBox() const
{
    return checkBox;
}

QByteArray CheckBoxPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked()){
        if(checkBox->isChecked()){
            ret = QByteArray(lab->text().toLocal8Bit()+" true")+end;
        }else{
            ret = QByteArray(lab->text().toLocal8Bit()+" false")+end;
        }
    }
    return ret;
}

bool CheckBoxPlug::lineGrabber(QByteArray line) const
{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    QRegularExpression re;
    re.setPattern("^"+lab->text()+"\\s+(?<varname>[a-zA-Z]+)\\s*$");
    if(re.match(line).hasMatch()){
        if(matchBoolTrue(re, line)){
            checkBox->setChecked(true);
            eckbox->setChecked(true);
        }else if(matchBoolFalse(re, line)){
            checkBox->setChecked(false);
            eckbox->setChecked(true);
        }
        return true;
    }
    return false;
}

bool CheckBoxPlug::getVersion_parameter() const
{
    return version_parameter;
}

void CheckBoxPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

bool CheckBoxPlug::matchBoolTrue(QRegularExpression r, QByteArray l) const{
    return r.match(l).captured("varname").toLower() == QString("true") ||
            r.match(l).captured("varname").toLower() == QString("yes");
}

bool CheckBoxPlug::matchBoolFalse(QRegularExpression r, QByteArray l) const{
    return r.match(l).captured("varname").toLower() == QString("false") ||
            r.match(l).captured("varname").toLower() == QString("no");
}

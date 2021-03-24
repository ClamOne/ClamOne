#include "StringListWidgetPlug.h"

StringListWidgetPlug::StringListWidgetPlug(QString name, QString tooltip)
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
    stringList = new QStringListWidget();
    stringList->setEnabled(false);
    hbox->addWidget(stringList);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        stringList->setEnabled(state);
    });
}

StringListWidgetPlug::~StringListWidgetPlug()
{

}

QCheckBox *StringListWidgetPlug::getEckbox() const
{
    return eckbox;
}

QStringListWidget *StringListWidgetPlug::getStringListWidget() const
{
    return stringList;
}

QByteArray StringListWidgetPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked()){
        QStringList tmp = stringList->getQStringList();
        foreach(QString line, tmp){
            ret.append(QByteArray(lab->text().toLocal8Bit()+" ")+line.toLocal8Bit()+end);
        }
    }
    return ret;
}

bool StringListWidgetPlug::lineGrabber(QByteArray line) const{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    QRegularExpression re;
    re.setPattern("^"+lab->text()+"\\s+(?<varname>[a-zA-Z0-9:\\/.^$]+)\\s*$");
    if(re.match(line).hasMatch()){
        QStringList tmp = stringList->getQStringList();
        tmp.append(re.match(line).captured("varname"));
        stringList->setQStringList(tmp);
        eckbox->setChecked(true);
        return true;
    }
    return false;
}

bool StringListWidgetPlug::getVersion_parameter() const
{
    return version_parameter;
}

void StringListWidgetPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

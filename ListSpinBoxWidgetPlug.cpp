#include "ListSpinBoxWidgetPlug.h"

ListSpinBoxWidgetPlug::ListSpinBoxWidgetPlug(QString name, QString tooltip){
    QHBoxLayout *hbox = new QHBoxLayout();
    setLayout(hbox);
    eckbox = new QCheckBox();
    hbox->addWidget(eckbox);
    lab = new QLabel(name);
    lab->setToolTip(tooltip);
    lab->setEnabled(false);
    hbox->addWidget(lab);
    hbox->addSpacerItem(new QSpacerItem(0,0, QSizePolicy::Expanding, QSizePolicy::Fixed));
    listSpinBox = new QListSpinBoxWidget();
    listSpinBox->setEnabled(false);
    hbox->addWidget(listSpinBox);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        listSpinBox->setEnabled(state);
    });
}

ListSpinBoxWidgetPlug::~ListSpinBoxWidgetPlug()
{

}

QCheckBox *ListSpinBoxWidgetPlug::getEckbox() const{
    return eckbox;
}

QListSpinBoxWidget *ListSpinBoxWidgetPlug::getListSpinBoxWidget() const
{
    return listSpinBox;
}

QByteArray ListSpinBoxWidgetPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked()){
        QList<int> tmp = listSpinBox->getQListInt();
        foreach(int num, tmp){
            ret.append(QByteArray(lab->text().toLocal8Bit()+" ")+QString::number(num).toLocal8Bit()+end);
        }
    }
    return ret;
}

bool ListSpinBoxWidgetPlug::lineGrabber(QByteArray line) const{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    QRegularExpression re;
    re.setPattern("^"+lab->text()+"\\s+(?<varname>[a-zA-Z]+)\\s*$");
    if(re.match(line).hasMatch()){
        QList<int> tmp = listSpinBox->getQListInt();
        QString tmpstr = re.match(line).captured("varname");
        bool ok;
        int tmpint = tmpstr.toInt(&ok, 10);
        if(!ok)
            return false;
        tmp.append(tmpint);
        listSpinBox->setQListInt(tmp);
        eckbox->setChecked(true);
        return true;
    }
    return false;
}

bool ListSpinBoxWidgetPlug::getVersion_parameter() const
{
    return version_parameter;
}

void ListSpinBoxWidgetPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

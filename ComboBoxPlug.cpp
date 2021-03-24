#include "ComboBoxPlug.h"

ComboBoxPlug::ComboBoxPlug(QString name, QString tooltip, QStringList cbox)
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
    comboBox = new QComboBox();
    comboBox->addItems(cbox);
    comboBox->setEnabled(false);
    hbox->addWidget(comboBox);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        comboBox->setEnabled(state);
    });
}

ComboBoxPlug::~ComboBoxPlug()
{

}

QCheckBox *ComboBoxPlug::getEckbox() const{
    return eckbox;
}

QComboBox *ComboBoxPlug::getComboBox() const{
    return comboBox;
}

QByteArray ComboBoxPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked() && !comboBox->currentText().isEmpty()){
        ret = QByteArray(lab->text().toLocal8Bit()+" ")+comboBox->currentText().toLocal8Bit()+end;
    }
    return ret;
}

bool ComboBoxPlug::lineGrabber(QByteArray line) const{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    QRegularExpression re;
    re.setPattern("^"+lab->text()+"\\s+(?<varname>[a-zA-Z0-9]+)\\s*$");
    if(re.match(line).hasMatch()){
        int total = comboBox->count();
        for(int i = 0; i < total; i++){
            QString text = comboBox->itemText(i);
            if(re.match(line).captured("varname").toLower() == text.toLower()){
                comboBox->setCurrentIndex(i);
                eckbox->setChecked(true);
                return true;
            }
        }
    }
    return false;
}

bool ComboBoxPlug::getVersion_parameter() const
{
    return version_parameter;
}

void ComboBoxPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

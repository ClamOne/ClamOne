#include "LineEditPlug.h"

LineEditPlug::LineEditPlug(QString name, QString tooltip, QString defaultText)
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
    lineEdit = new QLineEdit();
    lineEdit->setText(defaultText);
    lineEdit->setEnabled(false);
    hbox->addWidget(lineEdit);
    connect(eckbox, &QCheckBox::stateChanged, [=](int state) {
        lab->setEnabled(state);
        lineEdit->setEnabled(state);
    });
}

LineEditPlug::~LineEditPlug(){

}

QCheckBox *LineEditPlug::getEckbox() const
{
    return eckbox;
}

QLabel *LineEditPlug::getLabel() const
{
    return lab;
}

QLineEdit *LineEditPlug::getLineEdit() const
{
    return lineEdit;
}

QByteArray LineEditPlug::toConfline() const
{
    LINE_END
    QByteArray ret = QByteArray();
    if(eckbox->isChecked()){
        ret = QByteArray(lab->text().toLocal8Bit()+" ")+lineEdit->text().toLocal8Bit()+end;
    }
    return ret;
}

bool LineEditPlug::lineGrabber(QByteArray line) const{
    if(!version_parameter){
        eckbox->setChecked(false);
        return false;
    }
    QRegularExpression re;
    re.setPattern("^"+lab->text()+"\\s+\"(?<varname>[a-zA-Z0-9\\'\\!\\@#$\\%\\^\\&\\*\\(\\)\\_\\-\\+\\=.\\,\\:\\;\\{\\}\\[\\]\\\\\\/ \t\\<\\>]+)\"\\s*$");
    if(re.match(line).hasMatch()){
        lineEdit->setText(re.match(line).captured("varname"));
        eckbox->setChecked(true);
        return true;
    }
    re.setPattern("^"+lab->text()+"\\s+\'(?<varname>[a-zA-Z0-9\\\"\\!\\@#$\\%\\^\\&\\*\\(\\)\\_\\-\\+\\=.\\,\\:\\;\\{\\}\\[\\]\\\\\\/ \t\\<\\>]+)\'\\s*$");
    if(re.match(line).hasMatch()){
        lineEdit->setText(re.match(line).captured("varname"));
        eckbox->setChecked(true);
        return true;
    }
    re.setPattern("^"+lab->text()+"\\s+(?<varname>[a-zA-Z0-9\\!\\@#$\\%\\^\\&\\*\\(\\)\\_\\-\\+\\=.\\,\\:\\;\\{\\}\\[\\]\\\\\\/\\<\\\"\'\\> ]+)\\s*$");
    if(re.match(line).hasMatch()){
        lineEdit->setText(re.match(line).captured("varname"));
        eckbox->setChecked(true);
        return true;
    }
    return false;
}

bool LineEditPlug::getVersion_parameter() const
{
    return version_parameter;
}

void LineEditPlug::setVersion_parameter(bool value)
{
    version_parameter = value;
}

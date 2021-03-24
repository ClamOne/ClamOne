#ifndef LINEEDITPLUG_H
#define LINEEDITPLUG_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QRegularExpression>
#include <QDebug>
#include "confs.h"

class LineEditPlug: public QWidget
{
Q_OBJECT

public:
    LineEditPlug(QString name, QString tooltip, QString defaultText);
    ~LineEditPlug();
    QCheckBox *getEckbox() const;
    QLabel *getLabel() const;
    QLineEdit *getLineEdit() const;
    QByteArray toConfline() const;
    bool lineGrabber(QByteArray line) const;

    bool getVersion_parameter() const;
    void setVersion_parameter(bool value);

private:
    QLabel *lab;
    QCheckBox *eckbox;
    QLineEdit *lineEdit;
    bool version_parameter = true;
};

#endif // LINEEDITPLUG_H

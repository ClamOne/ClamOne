#ifndef CHECKBOXPLUG_H
#define CHECKBOXPLUG_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>
#include <QRegularExpression>

#include <QDebug>

#include "confs.h"

class CheckBoxPlug: public QWidget
{
    Q_OBJECT
public:
    CheckBoxPlug(QString name, QString tooltip, bool defaultState);
    ~CheckBoxPlug();
    QCheckBox *getEckbox() const;
    QCheckBox *getCheckBox() const;
    QByteArray toConfline() const;
    bool lineGrabber(QByteArray line) const;

    bool getVersion_parameter() const;
    void setVersion_parameter(bool value);

private:
    QCheckBox *eckbox;
    QCheckBox *checkBox;
    QLabel *lab;
    bool version_parameter = true;

    bool matchBoolTrue(QRegularExpression r, QByteArray l) const;
    bool matchBoolFalse(QRegularExpression r, QByteArray l) const;
};

#endif // CHECKBOXPLUG_H

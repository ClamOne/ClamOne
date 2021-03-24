#ifndef SPINBOXPLUG_H
#define SPINBOXPLUG_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>
#include <QSpinBox>

#include "confs.h"

class SpinBoxPlug: public QWidget
{
Q_OBJECT

public:
    SpinBoxPlug(QString name, QString tooltip, int min, int max, int defaultNum, int displayBase = 10);
    ~SpinBoxPlug();
    QCheckBox *getEckbox() const;
    QSpinBox *getSpinBox() const;
    QByteArray toConfline() const;
    bool lineGrabber(QByteArray line) const;

    bool getVersion_parameter() const;
    void setVersion_parameter(bool value);

private:
    QCheckBox *eckbox;
    QSpinBox *spinBox;
    QLabel *lab;
    bool version_parameter = true;

    int toClamInt(QString in, bool *ok) const;
};

#endif // SPINBOXPLUG_H

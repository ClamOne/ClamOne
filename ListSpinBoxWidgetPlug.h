#ifndef LISTSPINBOXWIDGETPLUG_H
#define LISTSPINBOXWIDGETPLUG_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>

#include "qlistspinboxwidget.h"
#include "confs.h"

class ListSpinBoxWidgetPlug : public QWidget
{
    Q_OBJECT
public:
    ListSpinBoxWidgetPlug(QString name, QString tooltip);
    ~ListSpinBoxWidgetPlug();
    QCheckBox *getEckbox() const;
    QListSpinBoxWidget *getStringListWidget() const;
    QByteArray toConfline() const;
    bool lineGrabber(QByteArray line) const;

    bool getVersion_parameter() const;
    void setVersion_parameter(bool value);

private:
    QCheckBox *eckbox;
    QListSpinBoxWidget *listSpinBox;
    QLabel *lab;
    bool version_parameter = true;
};

#endif // LISTSPINBOXWIDGETPLUG_H

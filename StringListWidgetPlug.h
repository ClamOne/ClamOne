#ifndef STRINGLISTWIDGETPLUG_H
#define STRINGLISTWIDGETPLUG_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>

#include "qstringlistwidget.h"
#include "confs.h"

class StringListWidgetPlug:public QWidget
{
    Q_OBJECT
public:
    StringListWidgetPlug(QString name, QString tooltip);
    ~StringListWidgetPlug();
    QCheckBox *getEckbox() const;
    QStringListWidget *getStringListWidget() const;
    QByteArray toConfline() const;
    bool lineGrabber(QByteArray line) const;

    bool getVersion_parameter() const;
    void setVersion_parameter(bool value);

private:
    QCheckBox *eckbox;
    QStringListWidget *stringList;
    QLabel *lab;
    bool version_parameter = true;
};

#endif // STRINGLISTWIDGETPLUG_H

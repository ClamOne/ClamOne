#ifndef COMBOBOXPLUG_H
#define COMBOBOXPLUG_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>
#include <QComboBox>
#include <QRegularExpression>

#include "confs.h"

class ComboBoxPlug : public QWidget
{
    Q_OBJECT
public:
    ComboBoxPlug(QString name, QString tooltip, QStringList cbox);
    ~ComboBoxPlug();
    QCheckBox *getEckbox() const;
    QComboBox *getComboBox() const;
    QByteArray toConfline() const;
    bool lineGrabber(QByteArray line) const;

    bool getVersion_parameter() const;
    void setVersion_parameter(bool value);

private:
    QCheckBox *eckbox;
    QComboBox *comboBox;
    QLabel *lab;
    bool version_parameter = true;
};

#endif // COMBOBOXPLUG_H

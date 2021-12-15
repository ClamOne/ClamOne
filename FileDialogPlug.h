#ifndef FileDialogPlug_H
#define FileDialogPlug_H

#include <QObject>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>
#include <QRegularExpression>
#include <QDebug>
#include "confs.h"

class FileDialogPlug: public QWidget
{
Q_OBJECT

public:
    FileDialogPlug(QString name, QString tooltip, QString defaultText, QString fileTypesFilter,
                   QFileDialog::Options options = QFileDialog::ShowDirsOnly);
    ~FileDialogPlug();
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
    QPushButton *pushButton;
    bool version_parameter = true;
};

#endif // FileDialogPlug_H

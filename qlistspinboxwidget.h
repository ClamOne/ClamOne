#ifndef QLISTSPINBOXWIDGET_H
#define QLISTSPINBOXWIDGET_H

#include <QWidget>
#include <QPushButton>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <QtUiPlugin/QDesignerExportWidget>

class QDESIGNER_WIDGET_EXPORT QListSpinBoxWidget : public QWidget
{
    Q_OBJECT
private slots:
    void incSize();
    void decSize();
    void changeIndex(int val);
    void changeSpinBoxValue(const int val);

public:
    explicit QListSpinBoxWidget(QWidget *parent = nullptr);
    const QList<int> getQListInt();
    void setQListInt(const QList<int> val);

private:
    QPushButton *pushButtonPlus;
    QPushButton *pushButtonMinus;
    QLabel *labelIndictor;
    QSpinBox *mainValueSpinBox;
    QSpinBox *spinBox;

    quint64 pos, size;

    QList<int> values;
    void updateIndicator();
};

#endif


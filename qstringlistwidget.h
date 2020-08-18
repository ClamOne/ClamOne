#ifndef QSTRINGLISTWIDGET_H
#define QSTRINGLISTWIDGET_H

#include <QWidget>
#include <QPushButton>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <QCryptographicHash>
#include <QtUiPlugin/QDesignerExportWidget>

class QDESIGNER_WIDGET_EXPORT QStringListWidget : public QWidget
{
    Q_OBJECT
private slots:
    void incSize();
    void decSize();
    void changeIndex(int val);
    void changeLineEdit(const QString val);
    void deleteButton();

signals:
    void stringlistChange();

public:
    explicit QStringListWidget(QWidget *parent = nullptr);
    const QStringList getQStringList();
    const QByteArray getBlob();
    void setQStringList(const QStringList val);

private:
    QPushButton *pushButtonPlus;
    QPushButton *pushButtonMinus;
    QPushButton *pushButtonDelete;
    QLabel *labelIndictor;
    QLineEdit *lineEdit;
    QSpinBox *spinBox;

    quint64 pos, size;

    QStringList strings;
    QByteArray oldhash;
    void checkIfStringlistChanged();
    void updateIndicator();
};

#endif


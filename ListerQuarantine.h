#ifndef LISTERQUARANTINE_H
#define LISTERQUARANTINE_H

#include <QDialog>
#include <QCloseEvent>
#include <QFileInfo>
#include <QDebug>

namespace Ui {
class ListerQuarantine;
}

class ListerQuarantine : public QDialog
{
    Q_OBJECT

private slots:
    void on_pushButtonYes_clicked();
    void on_pushButtonNo_clicked();

public slots:
    void add_file(QByteArray crypt_filename, QByteArray plain_filename);

signals:
    void yesClicked();
    void noClicked();
    void refreshEventFound(qint64 page, bool reset_position);

public:
    explicit ListerQuarantine(QWidget *parent = 0);
    ~ListerQuarantine();

private:
    Ui::ListerQuarantine *ui;
    QList<QPair<QByteArray, QByteArray> > internal;

    bool remove_from_list(QByteArray *crypt_filename, QByteArray *plain_filename);
    bool exts(QByteArray crypt_filename, QByteArray plain_filename);

protected:
    void closeEvent(QCloseEvent *event) override;
};

#endif // LISTERQUARANTINE_H

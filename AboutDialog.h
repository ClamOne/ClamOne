#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QDialog>
#include <QCloseEvent>

#include "confs.h"

namespace Ui {
class AboutDialog;
}

class AboutDialog : public QDialog
{
    Q_OBJECT
private slots:
    void on_pushButtonOk_clicked();

public:
    explicit AboutDialog(QWidget *parent = 0);
    ~AboutDialog();

private:
    Ui::AboutDialog *ui;

protected:
    void closeEvent(QCloseEvent *event) override;
};

#endif // ABOUTDIALOG_H

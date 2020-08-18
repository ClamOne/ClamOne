#ifndef SCHEDULEITEM_H
#define SCHEDULEITEM_H

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>

class ScheduleItem : public QWidget
{
    Q_OBJECT
public:
    explicit ScheduleItem(QWidget *parent = nullptr);
    ~ScheduleItem();

signals:

public slots:
};

#endif // SCHEDULEITEM_H

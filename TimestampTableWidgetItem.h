#ifndef TIMESTAMPTABLEWIDGETITEM_H
#define TIMESTAMPTABLEWIDGETITEM_H

#include <QObject>
#include <QTableWidgetItem>
#include <QDateTime>

#include <QDebug>

class TimestampTableWidgetItem: public QTableWidgetItem
{
public:
    TimestampTableWidgetItem(quint32 ts);
    bool operator< (QTableWidgetItem &other) const;
    bool operator> (QTableWidgetItem &other) const;
    quint32 getTimestamp() const;

private:
    quint32 timestamp;
};

#endif // TIMESTAMPTABLEWIDGETITEM_H

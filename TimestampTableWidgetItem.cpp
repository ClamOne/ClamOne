#include "TimestampTableWidgetItem.h"

TimestampTableWidgetItem::TimestampTableWidgetItem(quint32 ts){
    timestamp = ts;
    if(ts)
        this->setText(
            QDateTime::fromMSecsSinceEpoch(((quint64)timestamp)*1000).toString("yyyy/MM/dd AP hh:mm:ss")
        );
    else
        this->setText("");
}

bool TimestampTableWidgetItem::operator<(QTableWidgetItem &other) const{
    quint32 ts = 0;
    QDateTime b = QDateTime::fromString(other.text(), "yyyy/MM/dd AP hh:mm:ss");
    if (b.isValid())
        ts = b.toMSecsSinceEpoch()/1000;
    return timestamp < ts;
}

quint32 TimestampTableWidgetItem::getTimestamp() const{
    quint32 ret = timestamp;
    return ret;
}


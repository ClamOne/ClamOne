#include "ScheduleItem.h"

ScheduleItem::ScheduleItem(QWidget *parent) : QWidget(parent){
    QLabel *text = new QLabel("HELLO WORLD");
    QVBoxLayout *qvbl = new QVBoxLayout(this);
    setLayout(qvbl);
    qvbl->addWidget(text);

}

ScheduleItem::~ScheduleItem(){

}

#-------------------------------------------------
#
# Project created by QtCreator 2020-01-29T17:42:20
#
#-------------------------------------------------

QT       += core gui
QT       += charts
QT       += network
QT       += sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ClamOne
TEMPLATE = app

unix:target.path = /usr/bin
unix:target.files = ClamOne

unix:conf.path = /usr/share/ClamOne
unix:conf.files = ubuntu_setup.sh

unix:manfile.path = /usr/share/man/man1/
unix:manfile.files = man/clamone.1.gz

INSTALLS += target conf
INSTALLS += manfile


# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
    AboutDialog.cpp \
    CheckBoxPlug.cpp \
    ComboBoxPlug.cpp \
    ConfigureDialog.cpp \
    LineEditPlug.cpp \
    ListSpinBoxWidgetPlug.cpp \
    MainWindow.cpp \
    Main.cpp \
    SpinBoxPlug.cpp \
    StringListWidgetPlug.cpp \
    qstringlistwidget.cpp \
    gUncompress.cpp \
    ScanDialog.cpp \
    QAES.cpp \
    Quarantiner.cpp \
    TimestampTableWidgetItem.cpp \
    ListerQuarantine.cpp \
    qlistspinboxwidget.cpp

HEADERS += \
    AboutDialog.h \
    CheckBoxPlug.h \
    ComboBoxPlug.h \
    ConfigureDialog.h \
    LineEditPlug.h \
    ListSpinBoxWidgetPlug.h \
    MainWindow.h \
    SpinBoxPlug.h \
    StringListWidgetPlug.h \
    qstringlistwidget.h \
    confs.h \
    gUncompress.h \
    ScanDialog.h \
    QAES.h \
    Quarantiner.h \
    TimestampTableWidgetItem.h \
    ListerQuarantine.h \
    qlistspinboxwidget.h

FORMS += \
    AboutDialog.ui \
    MainWindow.ui \
    ScanDialog.ui \
    ListerQuarantine.ui

RESOURCES += \
    mainwindow.qrc \
    qstringlistwidget.qrc \
    translations.qrc \
    qlistspinboxwidget.qrc

TRANSLATIONS += \
    translations/co_de.ts \
    translations/co_fr.ts \
    translations/co_ko.ts \
    translations/co_es.ts

unix:contains(QMAKE_HOST.arch, x86_64):{
    LIBS += -lstdc++fs -lz
}

DISTFILES += \
    garbage2 \
    accesnt_chars.txt



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

TARGET = ClamOne.run
TEMPLATE = app

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
    FileDialogPlug.cpp \
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
    FileDialogPlug.h \
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
    ScanDialog.ui \
    ListerQuarantine.ui
    #MainWindow.ui \

RESOURCES += \
    mainwindow.qrc \
    qstringlistwidget.qrc \
#    translations.qrc \
    qlistspinboxwidget.qrc

#TRANSLATIONS += 

unix:{
    LIBS += -lstdc++fs -lz

    isEmpty(PREFIX){
        PREFIX = /usr
    }
    target.path = $$PREFIX/bin
    target.files = ClamOne

    shortcutfiles.files = clamone.desktop
    shortcutfiles.path = $$PREFIX/share/applications/
    data.files = images/main_icon_grey.png
    data.path = $$PREFIX/share/pixmaps/

    conf.files = ubuntu_setup.sh
    conf.path = $$PREFIX/share/ClamOne/

    manfile.files = man/clamone.1.gz
    manfile.path = $$PREFIX/share/man/man1/

    INSTALLS += shortcutfiles
    INSTALLS += data
    INSTALLS += conf
    INSTALLS += manfile
}

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /usr/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES +=



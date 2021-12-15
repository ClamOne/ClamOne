#include <QApplication>
#include <QTranslator>
#include <QTimer>
#include <QObject>
#include <QRegularExpression>

#include "MainWindow.h"
#include "ConfigureDialog.h"

#ifndef CLAMONE_DEBUG
void myMessageOutput(QtMsgType type, const QMessageLogContext &context, const QString &msg);
#endif

int main(int argc, char *argv[])
{
#ifndef CLAMONE_DEBUG
    qInstallMessageHandler(myMessageOutput);
#endif
    QApplication a(argc, argv);
    //QTranslator translator(NULL);
    //if(translator.load(QLocale(), QLatin1String("co"), QLatin1String("_"), QLatin1String(":/translations")))
    //    qApp->installTranslator(&translator);

    MainWindow w;
    QObject::connect(&a, &QApplication::aboutToQuit, &w, &MainWindow::aboutToQuit);
#ifdef CLAMONE_DEBUG
    w.show();
#else
    w.hide();
    qApp->setQuitOnLastWindowClosed(false);
#endif

    return a.exec();
}

#ifndef CLAMONE_DEBUG
void myMessageOutput(__attribute__((unused))QtMsgType type, const __attribute__((unused))QMessageLogContext &context, const __attribute__((unused))QString &msg){
}
#endif

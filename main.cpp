#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("QAuth");
    app.setOrganizationName("QAuth");
    MainWindow w;
    w.show();
    return app.exec();
}

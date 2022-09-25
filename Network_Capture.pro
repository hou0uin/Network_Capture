QT       += core gui
QT       += charts

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11 console

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS WPCAP HAVE_REMOTE _WINSOCK_DEPRECATED_NO_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    fun.cpp \
    main.cpp \
    package.cpp \
    shark.cpp \
    workerthread.cpp

HEADERS += \
    fun.h \
    header.h \
    package.h \
    shark.h \
    workerthread.h

FORMS += \
    shark.ui

INCLUDEPATH += D:/WpdPack/Include
LIBS += D:/WpdPack/Lib/wpcap.lib

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    src/src.qrc

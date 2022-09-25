#ifndef FUN_H
#define FUN_H
#include <QThread>
#include <QDebug>
#include "pcap.h"
#include "header.h"
#include "package.h"
#include "WinSock2.h"
class fun
{
public:
    fun();
    static QString uctoIP(u_char* ip);
    static QString fun::ultoIP(u_long ip);
    static QString byteToHex(u_char* str, int size);
    static QString uctoMAC(u_char* mac);
};

#endif // FUN_H

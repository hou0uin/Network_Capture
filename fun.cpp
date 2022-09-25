#include "fun.h"


fun::fun()
{

}

// 转换为IP
QString fun::uctoIP(u_char* ip)
{
    QString res = "";
    res = QString::number(*ip) + "."
        + QString::number(*(ip + 1)) + "."
        + QString::number(*(ip + 2)) + "."
        + QString::number(*(ip + 3));
    return res;
}

QString fun::ultoIP(u_long ip)
{
    sockaddr_in addr;
    addr.sin_addr.s_addr = ip;
    return QString(inet_ntoa(addr.sin_addr));
}


//转换为MAC
QString fun::uctoMAC(u_char* mac)
{
    QString res = "";
    for(int i = 0; i < 6; i++)
    {
        res += QString("%1").arg(mac[i], 2, 16, QChar('0'));
        if(i != 5)
            res += ":";
    }
    return res;
}

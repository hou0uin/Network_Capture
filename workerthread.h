#ifndef WORKERTHREAD_H
#define WORKERTHREAD_H
#include <QThread>
#include <QMutex>
#include <QDebug>
#include "pcap.h"
#include "header.h"
#include "package.h"
#include <windows.h>

#pragma comment(lib, "WS2_32.lib")

//多线程
class WorkerThread:public QThread
{
    Q_OBJECT //需要使用槽
public:
    WorkerThread();
    void setHandel(pcap_t* adhandle);
    void setFlag(int f);
    void run() override;    //重载，实现多线程

    QMutex mutex;

    //从以太网层抓包，解析以太网帧
//    int ethernetPackageHandle(const u_char *pkt_content, QString& info);
    int ipv4PackageHandle(const u_char *data, int& ip_package);   //返回协议
    QString tcpPackageHandle(const u_char *data, QString& info, int ip_package);   //指向数据内容的指针，存储信息的字段，ip包数据
    QString udpPackageHandle(const u_char *data, QString& info);
    QString arpPackageHandle(const u_char *data, QString& info);
    QString dnsPackageHandle(const u_char *data, QString& info);
    QString icmpPackageHandle(const u_char *data, QString& info);

    QString packageHandle(const u_char* data, QString& info);

private:
    pcap_t* adhandle;
    struct pcap_pkthdr* header; //数据包头部
    const u_char* pkt_data;     //数据包内容
    int flag;



    DWORD time_start;
signals:
    void send(Package data);    //信号
};

#endif // WORKERTHREAD_H

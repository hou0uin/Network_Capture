#include "workerthread.h"

#include "fun.h"

WorkerThread::WorkerThread()
{
    flag = 1;
}

void WorkerThread::setHandel(pcap_t* adhandle)
{
    this->adhandle = adhandle;
}

void WorkerThread::setFlag(int f)
{
    flag = f;
}

void WorkerThread::run()
{
    unsigned int number_package = 0;
    time_start = GetTickCount();
    // 开始抓包
    while(flag)
    {
//        mutex.lock();
        int res = pcap_next_ex(adhandle,&header,&pkt_data);
//        mutex.unlock();

        if(res == 0)
            continue;

        char timeString[16];
        time_t local_time_version_sec = header->ts.tv_sec;
        struct tm local_time;
        localtime_s(&local_time,&local_time_version_sec);
        strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);

        DWORD time_end = GetTickCount();
        QString timeStr = "";
        timeStr = timeString;
        //精确到毫秒
//        timeStr+= " "+ QString::number(time_end - time_start);
        QString info = "";


        QString type = packageHandle(pkt_data,info);
        if(type != "")
        {
            Package data;
            int len = header->len;
            data.setPackageType(type);
            data.setTimeStamp(timeStr);
            data.setDataLength(len);
            data.setPointer(pkt_data,len);
            data.setInfo(info);
            if(data.pkt_content != nullptr)
            {
//                mutex.lock();
                emit send(data);
//                mutex.unlock();
                number_package++;
            }else
                continue;
        }
        else
            continue;
    }
    return;
}

QString WorkerThread::packageHandle(const u_char* data, QString& info)
{
    info = "";
    ETH_HEADER* eth;
    u_short eth_type;
    eth = (ETH_HEADER*)data;
    eth_type = ntohs(eth->type);
//    qDebug()<<"---------------------ETH \n type: "<<eth_type;
    data += 14;

    switch (eth_type)
    {
    case 0x0800:
    {// IP
        IP_HEADER* ip = (IP_HEADER*)data;
        u_short protocol = ip->protocol;
        u_short datalen = Package::get_ip_TotalLength(data).toInt() - Package::get_ip_HeaderLength(data).toInt();
//        qDebug()<<"protocol: "<<protocol;
        data += Package::get_ip_HeaderLength(data).toInt();

        switch (protocol){  //判断IP包中protocol
        case 1:{// ICMP
            return icmpPackageHandle(data, info);
        }
        case 6:{// TCP
            return tcpPackageHandle(data, info, datalen);
        }
        case 17:{ // UDP
            return udpPackageHandle(data, info);
        }
        default:
            return "IP";
        }
        break;
    }
    case 0x0806:
    {// ARP
        return arpPackageHandle(data, info);
    }
    default:
    {
        break;
    }
    }
    return "UNKNOW";
}


int WorkerThread::ipv4PackageHandle(const u_char* data, int& ip_package)
{
    IP_HEADER* ip = (IP_HEADER*)data;    //跳过eth头
    ip_package = (htons(ip->total_length) - (ip->versiosn_head_length & 0x0F) * 4); //计算数据部分长度
    return ip->protocol;
}

QString WorkerThread::tcpPackageHandle(const u_char* data, QString& info, int ip_package)
{
    info = "";
    TCP_HEADER* tcp = (TCP_HEADER*)data;

    int len = ip_package - Package::get_tcp_HeaderLength(data).toInt();        //数据包载荷

    info += Package::get_tcp_SourcePort(data) +"->" + Package::get_tcp_DestinationPort(data);

    //获取标志位
    info += " [" + Package::get_tcp_Flags_info(tcp) + "] ";

    //窗口大小，序列号
    info += "Seq=" + Package::get_tcp_SequenceNumber(data) + " Ack=" + Package::get_tcp_AcknowledgmentNumver(data)
            +" Win="+Package::get_tcp_WindowSizeValue(data) + " Len=" + QString::number(len);

//    qDebug()<<"---------------------TCP";
    return "TCP";
}

QString WorkerThread::udpPackageHandle(const u_char* data, QString& info)
{
    UDP_HEADER* udp = (UDP_HEADER*)data;
    //upd端口
    u_short srcPort = ntohs(udp->src_port);
    u_short desPort = ntohs(udp->des_port);

    //upd 53 DNS
    if (desPort == 53 || srcPort == 53)
        return dnsPackageHandle(data + 8, info);

    info = QString::number(srcPort) + "->" + QString::number(desPort);
    info += " len=" + QString::number(ntohs(udp->data_length));

//    qDebug()<<"---------------------UDP";
    return "UDP";
}

QString WorkerThread::arpPackageHandle(const u_char* data, QString& info)
{

    ARP_HEADER* arp = (ARP_HEADER*)data;
    QString desIP = fun::ultoIP(arp->des_ip);
    QString srcIP = fun::ultoIP(arp->src_ip);
    QString srcMAC = fun::uctoMAC(arp->src_mac);
    u_short op = ntohs(arp->op);
//    qDebug()<<"---------------------ARP \n op: "<<op;
    info = "";

    //op操作码判断
    if(op == 1)
        info  = "Who has " + desIP + " ? Tell " + srcIP;
    else if(op == 2)
        info = srcIP + " is at " + srcMAC;
    if(desIP == srcIP)
        info = "Gratuitous ARP for " + srcIP + " (Request)";
    return "ARP";
}

QString WorkerThread::dnsPackageHandle(const u_char *data, QString& info)
{
    DNS_HEADER* dns = (DNS_HEADER*)data;
    u_short identification = ntohs(dns->identification);
    u_short flags = dns->flags;
//    qDebug()<<"---------------------DNS \n flags: "<<flags<<" identification: "<<identification;
    info="";

    if((flags & 0xf800) == 0x0000)  //取出第一位
        info = "Standard query ";
    else if((flags & 0xf800) == 0x0000)
        info = "Standard query response ";

    //域名
    QString domain = "";
    char* p = (char*)(data + 12);
    while(*p != 0x00)
    {
        if(p && (*p) <= 64)
        {
            int len = *p;   //获得一段长度
            p++;
            for(int i = 0; i < len; i++)
                domain+= *(p++);
            if(*p != 0x00)
                domain += ".";
        }
        else
            break;
    }
    info += "0x" + QString::number(identification,16) + " " + domain;

//    qDebug()<<"---------------------DNS";
    return "DNS";
}

QString WorkerThread::icmpPackageHandle(const u_char *data, QString& info)
{
    ICMP_HEADER* icmp = (ICMP_HEADER*)data;
    u_char type = icmp->type;
    u_char code = icmp->code;
//    qDebug()<<"---------------------ICMP \n type: "<<type<<" code: "<<code;
    info = "";
    switch (type) {
    case 0:{
        if(code == 0)
            info = "Echo response(ping)";
        break;
    }
    case 8:{
        if(code == 0)
            info = "Echo request(ping)";
        break;
    }
    default:
        break;
    }
    return "ICMP";
}












































#include "package.h"
#include "fun.h"
#include "WinSock2.h"
#include <QMetaType>


Package::Package()
{
    qRegisterMetaType<Package>("Package"); //信号注册

    this->timeStamp = "";
    this->dataLen = 0;
    this->packageType = "";
    this->pkt_content = NULL;
}

//-------------------------------------------------------------------------------

void Package::setDataLength(const unsigned int& length){
    this->dataLen = length;
}

void Package::setTimeStamp(const QString& timeStamp){
    this->timeStamp = timeStamp;
}

void Package::setPackageType(const QString& type){
    this->packageType = type;
}

void Package::setPointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char*)malloc(size);
    //保存抓到的包
    if(this->pkt_content != NULL)
        memcpy((char*)(this->pkt_content),pkt_content,size);
    else
        this->pkt_content = NULL;
}

void Package::setInfo(const QString& info){
    this->info = info;
}

//-------------------------------------------------------------------------------

QString Package::getTimeStamp(){
    return this->timeStamp;
}

QString Package::getDataLength(){
    return QString::number(this->dataLen);
}

QString Package::getPackageType(){
    return packageType;
}

QString Package::getSource()
{
    if(this->packageType == "ARP")
        return this->get_eth_Src(pkt_content);
    return this->get_ip_Source(pkt_content + 14);
}

QString Package::getDestination()
{
    if(this->packageType == "ARP")
        return this->get_eth_Des(pkt_content);
    return this->get_ip_Destination(pkt_content + 14);
}

QString Package::getInfo(){
    return info;
}

//-------------------------------------------------------------------------------

QString Package::get_eth_Des(const u_char *data){
    ETH_HEADER* eth;
    eth = (ETH_HEADER*)data;
    u_char*addr;
    if(eth){
        addr = eth->des_mac;
        if(addr){
            QString res = fun::uctoMAC(addr);
            if(res == "ff:ff:ff:ff:ff:ff")  // 如果是广播地址
                return "Broadcast";
            return res;
        }
    }
    return "";
}

QString Package::get_eth_Src(const u_char *data){
    ETH_HEADER* eth;
    eth = (ETH_HEADER*)data;
    u_char*addr;
    if(eth){
        addr = eth->src_mac;
        if(addr){
            QString res = fun::uctoMAC(addr);
            if(res == "ff:ff:ff:ff:ff:ff")  // 如果是广播地址
                return "Broadcast";
            return res;
        }
    }
    return "";
}

QString Package::get_eth_Type(const u_char *data){
    ETH_HEADER* eth;
    eth = (ETH_HEADER*)data;
    u_short type = ntohs(eth->type);
    QString r = "0x" + QString("%1").arg(ntohs(eth->type), 4, 16, QChar('0'));
    if(type == 0x0800)
        return "IP (" + r + ")";
    else if(type == 0x0806)
        return "ARP (" + r + ")";
    return "UNKNOW (" + r + ")";
}

//-----------------------------------------------------------IP
QString Package::get_ip_Version(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)(data);
    return QString::number(ip->versiosn_head_length >> 4);
}

QString Package::get_ip_HeaderLength(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    int length = (ip->versiosn_head_length & 0x0F) * 4;
    return QString::number(length);
}

QString Package::get_ip_DifferentiatedServicesField(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    return "0x" + QString("%1").arg(ip->TOS, 2, 16, QChar('0'));
}

QString Package::get_ip_TotalLength(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    return QString::number(ntohs(ip->total_length));
}

QString Package::get_ip_Identification(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    return "0x" + QString("%1").arg(ntohs(ip->identification), 4, 16, QChar('0'));
}

QString Package::get_ip_Flags(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    return "0x" + QString("%1").arg((ntohs(ip->flag_offset)& 0xe000) >> 13, 2, 16, QChar('0'));
}

QString Package::get_ip_Flags_RB(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    if(((ntohs(ip->flag_offset) & 0x8000) >> 15) == 1)
        return "Set";
    return "Not set";
}

QString Package::get_ip_Flags_DF(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    if(((ntohs(ip->flag_offset) & 0x4000) >> 14) == 1)
        return "Set";
    return "Not set";
}

QString Package::get_ip_Flags_MF(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    if(((ntohs(ip->flag_offset) & 0x4000) >> 13) == 1)
        return "Set";
    return "Not set";
}

QString Package::get_ip_FragmentOffset(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}

QString Package::get_ip_TimeToLive(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    return QString::number(ip->ttl);
}

QString Package::get_ip_Protocol(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    int protocol = ip->protocol;

//    qDebug()<<protocol;

    if(protocol == 1)
        return "ICMP";
    if(protocol == 6)
        return "TCP";
    if(protocol == 17)
        return "UDP";

    return "UNKNOW (" + QString::number(protocol) + ")";
}

QString Package::get_ip_HeaderChecksum(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;

    return "0x" + QString("%1").arg(ntohs(ip->checksum), 4, 16, QChar('0'));
}

QString Package::get_ip_Source(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    sockaddr_in addr;
    addr.sin_addr.s_addr = ip->src_ip;
    return QString(inet_ntoa(addr.sin_addr));
}

QString Package::get_ip_Destination(const u_char *data){
    IP_HEADER* ip = (IP_HEADER*)data;
    sockaddr_in addr;
    addr.sin_addr.s_addr = ip->des_ip;
    return QString(inet_ntoa(addr.sin_addr));
}

//-----------------------------------------------------------ICMP

QString Package::get_icmp_Type(const u_char *data){
    ICMP_HEADER* icmp = (ICMP_HEADER*)data;
//    qDebug()<<" zq: "<<icmp->type<<" zh:"<<ntohs(icmp->type);
    return QString::number(icmp->type);
}

QString Package::get_icmp_Code(const u_char *data){
    ICMP_HEADER* icmp = (ICMP_HEADER*)data;
    return QString::number(ntohs(icmp->code));
}

QString Package::get_icmp_Checksum(const u_char *data){
    ICMP_HEADER* icmp = (ICMP_HEADER*)data;
    return "0x" + QString("%1").arg(ntohs(icmp->checksum), 4, 16, QChar('0'));
}

QString Package::get_icmp_Identifier(const u_char *data){
    ICMP_HEADER* icmp = (ICMP_HEADER*)data;
    return QString::number(ntohs(icmp->identification));
}

QString Package::get_icmp_SequenceNumber(const u_char *data){
    ICMP_HEADER* icmp = (ICMP_HEADER*)data;
    return QString::number(ntohs(icmp->sequence));
}

//-----------------------------------------------------------TCP

QString Package::get_tcp_SourcePort(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number(ntohs(tcp->src_port));
}

QString Package::get_tcp_DestinationPort(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number(ntohs(tcp->des_port));
}

//实际序列号/确认号
QString Package::get_tcp_SequenceNumber(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number(ntohl(tcp->sequence));
}

QString Package::get_tcp_AcknowledgmentNumver(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number(ntohl(tcp->ack));
}

QString Package::get_tcp_HeaderLength(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number((ntohs(tcp->header_length_flags) >> 12) * 4);
}

QString Package::get_tcp_Flags(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return "0x" + QString("%1").arg(ntohs(tcp->header_length_flags & 0x0fff), 3, 16, QChar('0'));
}

QString Package::get_tcp_Flags_info(TCP_HEADER *tcp){
    QString flag = "";
    if (ntohs(tcp->header_length_flags) & 0x20) flag += "URG, ";
    if (ntohs(tcp->header_length_flags) & 0x10) flag += "ACK, ";
    if (ntohs(tcp->header_length_flags) & 0x08) flag += "PSH, ";
    if (ntohs(tcp->header_length_flags) & 0x04) flag += "RST, ";
    if (ntohs(tcp->header_length_flags) & 0x02) flag += "SYN, ";
    if (ntohs(tcp->header_length_flags) & 0x01) flag += "FIN, ";
    if (flag != "") {
        flag = flag.left(flag.length() - 2);
    }
    return flag;
}

QString Package::get_tcp_Flags_Reserved(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if((ntohs(tcp->header_length_flags) & 0xe00))
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_Nonce(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x100)
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_CWR(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x080)
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_ECN(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x040)
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_Urgent(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x020)
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_ACK(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x010)
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_Push(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x008)return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_Reset(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x004)return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_SYN(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x002)
        return "Set";
    return "Not set";
}
QString Package::get_tcp_Flags_FIN(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    if(ntohs(tcp->header_length_flags) & 0x001)
        return "Set";
    return "Not set";
}

QString Package::get_tcp_WindowSizeValue(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number(ntohs(tcp->window_size));
}

QString Package::get_tcp_Checksum(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return "0x" + QString("%1").arg(ntohs(tcp->checksum), 4, 16, QChar('0'));
}

QString Package::get_tcp_UrgentPointer(const u_char *data){
    TCP_HEADER* tcp = (TCP_HEADER*)data;
    return QString::number(ntohs(tcp->urgent));
}

//-----------------------------------------------------------UDP

QString Package::get_udp_SourcePort(const u_char *data){
    UDP_HEADER* udp = (UDP_HEADER*)data;
    return QString::number(ntohs(udp->src_port));
}

QString Package::get_udp_DestinationPort(const u_char *data){
    UDP_HEADER* udp = (UDP_HEADER*)data;
    return QString::number(ntohs(udp->des_port));
}

QString Package::get_udp_Length(const u_char *data){
    UDP_HEADER* udp = (UDP_HEADER*)data;
    return QString::number(ntohs(udp->data_length));
}

QString Package::get_udp_Checksum(const u_char *data){
    UDP_HEADER* udp = (UDP_HEADER*)data;
    return "0x" + QString("%1").arg(ntohs(udp->checksum), 4, 16, QChar('0'));
}


//-----------------------------------------------------------ARP

QString Package::get_arp_HardwareType(const u_char *data){
    ARP_HEADER* arp = (ARP_HEADER*)data;
    int type = ntohs(arp->hardware_type);
    if(type == 0x0001)
        return "Ethernet (1)";
    return QString::number(type);
}

QString Package::get_arp_ProtocolType(const u_char *data){
    ARP_HEADER* arp = (ARP_HEADER*)data;
    int type = ntohs(arp->protocol_type);
    if(type == 0x0800)
        return "IP (0x0800)";
    return QString::number(type);
}

QString Package::get_arp_HardwareSize(const u_char *data){
    ARP_HEADER* arp = (ARP_HEADER*)data;
    return QString::number(arp->mac_len);
}

QString Package::get_arp_ProtocolSize(const u_char *data){
    ARP_HEADER* arp = (ARP_HEADER*)data;
    return QString::number(arp->ip_len);
}

QString Package::get_arp_Opcode(const u_char *data){
    ARP_HEADER* arp = (ARP_HEADER*)data;
    int op = ntohs(arp->op);
    if(op == 1)
        return "request";
    if(op == 2)
        return "reply";
    return QString::number(op);
}

QString Package::get_arp_SenderMac(const u_char *data)
{
    ARP_HEADER* arp = (ARP_HEADER*)data;
    QString mac = fun::uctoMAC(arp->src_mac);
    if(mac == "ff:ff:ff:ff:ff")
        mac = "00:00:00:00:00";
    return mac;
}

QString Package::get_arp_SenderIp(const u_char *data)
{
    ARP_HEADER* arp = (ARP_HEADER*)data;
    sockaddr_in addr;
    addr.sin_addr.s_addr = arp->src_ip;
    return QString(inet_ntoa(addr.sin_addr));
}

QString Package::get_arp_TargetMac(const u_char *data)
{
    ARP_HEADER* arp = (ARP_HEADER*)data;
    QString mac = fun::uctoMAC(arp->des_mac);
    if(mac == "ff:ff:ff:ff:ff")
        mac = "00:00:00:00:00";
    return mac;
}

QString Package::get_arp_TargetIp(const u_char *data)
{
    ARP_HEADER* arp = (ARP_HEADER*)data;
    sockaddr_in addr;
    addr.sin_addr.s_addr = arp->des_ip;
    return QString(inet_ntoa(addr.sin_addr));
}

//-----------------------------------------------------------IP

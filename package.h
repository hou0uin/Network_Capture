#ifndef PACKAGE_H
#define PACKAGE_H

#define ARP_TYPE 1
#define ICMP_TYPE 2
#define TCP_TYPE 3
#define UDP_TYPE 4
#define DNS_TYPE 5
#define TLS_TYPE 6
#define SSL_TYPE 7

#include <QString>
#include "header.h"


class Package
{
private:
    u_int dataLen;      // 数据包长度
    QString timeStamp;  // 时间戳
    QString info;       // 信息
    QString packageType;    // 类型

public:
    Package();
    const u_char *pkt_content; // 指向内容的指针

    //set
    void setDataLength(const unsigned int& length);
    void setTimeStamp(const QString& timeStamp);
    void setPackageType(const QString& type);
    void setPointer(const u_char *pkt_content,int size);
    void setInfo(const QString& info);

    // get
    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
    QString getInfo();

    QString getSource();
    QString getDestination();

    // eth
    static QString get_eth_Des(const u_char *data);
    static QString get_eth_Src(const u_char *data);
    static QString get_eth_Type(const u_char *data);

    // ip
    static QString getDesIpAddr();
    static QString getSrcIpAddr();

    static QString get_ip_Version(const u_char *data);
    static QString get_ip_HeaderLength(const u_char *data);
    static QString get_ip_DifferentiatedServicesField(const u_char *data);
    static QString get_ip_TotalLength(const u_char *data);
    static QString get_ip_Identification(const u_char *data);
    static QString get_ip_Flags(const u_char *data);
    static QString get_ip_Flags_RB(const u_char *data);
    static QString get_ip_Flags_DF(const u_char *data);
    static QString get_ip_Flags_MF(const u_char *data);
    static QString get_ip_FragmentOffset(const u_char *data);
    static QString get_ip_TimeToLive(const u_char *data);
    static QString get_ip_Protocol(const u_char *data);
    static QString get_ip_HeaderChecksum(const u_char *data);
    static QString get_ip_Source(const u_char *data);
    static QString get_ip_Destination(const u_char *data);

    // icmp
    static QString get_icmp_Type(const u_char *data);
    static QString get_icmp_Code(const u_char *data);
    static QString get_icmp_Checksum(const u_char *data);
    static QString get_icmp_Identifier(const u_char *data);
    static QString get_icmp_SequenceNumber(const u_char *data);

    // tcp
    static QString get_tcp_SourcePort(const u_char *data);
    static QString get_tcp_DestinationPort(const u_char *data);
    static QString get_tcp_SequenceNumber(const u_char *data);
    static QString get_tcp_AcknowledgmentNumver(const u_char *data);
    static QString get_tcp_HeaderLength(const u_char *data);

    static QString get_tcp_Flags(const u_char *data);
    static QString get_tcp_Flags_info(TCP_HEADER *tcp);
    static QString get_tcp_Flags_Reserved(const u_char *data);
    static QString get_tcp_Flags_Nonce(const u_char *data);
    static QString get_tcp_Flags_CWR(const u_char *data);
    static QString get_tcp_Flags_ECN(const u_char *data);
    static QString get_tcp_Flags_Urgent(const u_char *data);
    static QString get_tcp_Flags_ACK(const u_char *data);
    static QString get_tcp_Flags_Push(const u_char *data);
    static QString get_tcp_Flags_Reset(const u_char *data);
    static QString get_tcp_Flags_SYN(const u_char *data);
    static QString get_tcp_Flags_FIN(const u_char *data);

    static QString get_tcp_WindowSizeValue(const u_char *data);
    static QString get_tcp_Checksum(const u_char *data);
    static QString get_tcp_UrgentPointer(const u_char *data);

    // udp
    static QString get_udp_SourcePort(const u_char *data);
    static QString get_udp_DestinationPort(const u_char *data);
    static QString get_udp_Length(const u_char *data);
    static QString get_udp_Checksum(const u_char *data);

    // arp
    static QString get_arp_HardwareType(const u_char *data);
    static QString get_arp_ProtocolType(const u_char *data);
    static QString get_arp_HardwareSize(const u_char *data);
    static QString get_arp_ProtocolSize(const u_char *data);
    static QString get_arp_Opcode(const u_char *data);
    static QString get_arp_SenderMac(const u_char *data);
    static QString get_arp_SenderIp(const u_char *data);
    static QString get_arp_TargetMac(const u_char *data);
    static QString get_arp_TargetIp(const u_char *data);

};

#endif // PACKAGE_H

#ifndef HEADER_H
#define HEADER_H

#include "pcap.h"

//对齐
#pragma pack (1)

/* Ethernet
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/
typedef struct ETH_HEADER{
    u_char  des_mac[6];     //目的MAC地址 6字节
    u_char  src_mac[6];     //源MAC地址 6字节
    u_short type;           //帧类型
}eth_header;


/* IPv4
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           | |D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct IP_HEADER{
    u_char  versiosn_head_length;   // 版本 和 部首长度
    u_char  TOS;                    // TOS/DS_byte
    u_short total_length;           // 总长度
    u_short identification;         // 标识符
    u_short flag_offset;            // 标志
    u_char  ttl;                    // TTL
    u_char  protocol;               // 协议号
    u_short checksum;               // 部首校验和
    u_long src_ip;               // 源IP地址
    u_long des_ip;               // 目的IP地址
}ip_header;


/* TCP
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct TCP_HEADER{
    u_short src_port;         // 源端口号
    u_short des_port;         // 目的端口号
    u_int   sequence;         // 序号seq
    u_int   ack;              // 确认序号 seq+1
    u_short  header_length_flags;    // 数据偏移 和 标志
//    u_char  flags;            // 标志
    u_short window_size;      // 窗口大小
    u_short checksum;         // 校验和
    u_short urgent;           // 紧急指针
}tcp_header;


/* UDP
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct UDP_HEADER{
    u_short src_port;      // 源端口号
    u_short des_port;      // 目标端口号
    u_short data_length;   // 包长度
    u_short checksum;      // 校验和
}udp_header;


/* ICMP 有多种类型
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct ICMP_HEADER{
    u_char  type;           // 类型
    u_char  code;           // 代码
    u_short checksum;       // 校验和
    u_short identification; // 标识符
    u_short sequence;
}icmp_header;



/* ARP
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/

typedef struct ARP_HEADER{
    u_short  hardware_type;     //硬件类型
    u_short  protocol_type;     //协议类型
    u_char   mac_len;           //硬件地址长度
    u_char   ip_len;            //协议地址长度
    u_short  op;                //op，操作类型
    u_char   src_mac[6];        //发送方MAC地址
    u_long   src_ip;            //发送方IP地址
    u_char   des_mac[6];        //目的MAC地址
    u_long   des_ip;            //目的IP地址
}arp_header;


/* DNS
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/

typedef struct DNS_HEADER{
    u_short identification; //
    u_short flags;          //
    u_short question;       //
    u_short answer;         //
    u_short authority;      //
    u_short additional;     //
}dns_header;

// dns question
typedef struct DNS_QUESITON{
    // char* name;          //
    u_short query_type;     //
    u_short query_class;    //
}dns_question;

typedef struct DNS_ANSWER{
    // char* name           //
    u_short answer_type;    //
    u_short answer_class;   //
    u_int TTL;              //
    u_short dataLength;     //
    //char* name            //
}dns_answer;


#pragma pack ()

#endif // HEADER_H


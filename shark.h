#ifndef SHARK_H
#define SHARK_H

#include <QMainWindow>
#include <QDebug>
#include <QVector>
#include <QObject>

#include <QDataStream>
#include <QFile>
#include <fstream>

#include "pcap.h"
#pragma comment(lib,"wpcap")

#include "workerthread.h"
#include "package.h"
#include "WinSock2.h"
#include <QChartView>
#include <QtCharts>
QT_CHARTS_USE_NAMESPACE
#include <QPieSlice>

QT_BEGIN_NAMESPACE
namespace Ui { class Shark; }
QT_END_NAMESPACE

class Shark : public QMainWindow
{
    Q_OBJECT

public:
    Shark(QWidget *parent = nullptr);
    ~Shark();
    void showDevices();
    int openDevice();
    int setFilter();

    bool setRules();    //设置规则
    void Visualize();

    void ClearGraphical();


private slots:
    void on_comboBox_currentIndexChanged(int index);

    void on_pushButton_clicked();
    void handleMessage(Package data);   //接收信号，处理信息
    void on_tableWidget_cellClicked(int row, int column);

    //点击扇形槽函数
//    void ClickedSector(QPieSlice* pSlice);

    void on_show_tcp_clicked();

    void on_show_udp_clicked();

    void on_show_icmp_clicked();

private:
    Ui::Shark *ui;

    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int device_count;

    pcap_t* adhandle;   //打开返回的WinPcap句柄
    int btnFlag;

    WorkerThread* thread;

    //多线程
    int thread_count;
    QVector<WorkerThread*> threads;

    QVector<Package> packages;      //包
    int packageCount;

    int selectRow;

    QVector<QString*> rules;      //保存规则
    QVector<int*> tcp_v;
    QVector<int*> udp_v;
    QVector<int*> icmp_v;

    std::ofstream log_file;

    QPieSeries* m_pPieSeries;
    QPieSlice* slice_tcp;
    QPieSlice* slice_udp;
    QPieSlice* slice_icmp;
    void show_tcp();
    void show_icmp();
    void show_udp();

    QString now_view;

//    QMap<QString, int> map;

    QMap<QString, QVector<QString*>> map;

    bool add_to_map(QString sip, QString dip,int num, int rule);

    void print_map(QMap<QString, int> &map);
    void show_package_count();

    QString view_eth();
    QString view_ip(const u_char* data,int &headerLength);
    QString view_icmp(const u_char* data);
    QString view_tcp(const u_char* data);
    QString view_udp(const u_char* data);
    QString view_arp(const u_char *data);

};

#endif // SHARK_H

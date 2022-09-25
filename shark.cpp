#include "shark.h"
#include "ui_shark.h"

#include <QChartView>
#include <QtCharts>
QT_CHARTS_USE_NAMESPACE
#include <QPieSlice>

//using namespace QtCharts;

Shark::Shark(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::Shark)
{
    ui->setupUi(this);
    showDevices();
    btnFlag = 0;
    packageCount = 0;

    //多线程
    thread_count = 1;
    for(int i = 0; i < thread_count; i++)
        threads.push_back(new WorkerThread());
    qDebug()<<"threads: "<<QString::number(threads.size());
    //将信号关联（信号的发送者，发送者地址，信号的接收者，接收者地址）
    for(int i = 0; i < threads.size(); i++)
    {
        connect(threads[i], &WorkerThread::send, this, &Shark::handleMessage);
    }

//    //单个线程
//    thread = new WorkerThread();
//    connect(thread, &WorkerThread::send, this, &Shark::handleMessage);

    selectRow = -1;

    //表格
    ui->tableWidget->setColumnCount(7);
    QStringList title = { "NO.","Time","Source","Destination","Protocol","Length","Info" };
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->setColumnWidth(0, 50);
    ui->tableWidget->setColumnWidth(1, 150);
    ui->tableWidget->setColumnWidth(2, 180);
    ui->tableWidget->setColumnWidth(3, 180);
    ui->tableWidget->setColumnWidth(4, 100);
    ui->tableWidget->setColumnWidth(5, 70);
    ui->tableWidget->setColumnWidth(6, 1000);

    //其他视觉效果
    ui->treeWidget->setHeaderHidden(true);
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->splitter->setStretchFactor(0,3);
    ui->splitter->setStretchFactor(0,2);
    ui->show_tcp->setStyleSheet("QPushButton{text-align : left;}");
    ui->show_udp->setStyleSheet("QPushButton{text-align : left;}");
    ui->show_icmp->setStyleSheet("QPushButton{text-align : left;}");

    ui->count->setHeaderHidden(true);

    //初始化规则地址
    ui->lineEdit->setText(":/rules.txt");

    m_pPieSeries = new QPieSeries;
    m_pPieSeries->setHoleSize(0.2);     //设置空心占比
    m_pPieSeries->setPieSize(0.8);      //设置圆形占比
    ui->pie_View->chart()->addSeries(m_pPieSeries);  //将饼图放入容器
    ui->pie_View->chart()->legend()->setAlignment(Qt::AlignRight);  //设置提示说明位置
    ui->pie_View->setRenderHint(QPainter::Antialiasing);    //渲染

//    connect(m_pPieSeries, SIGNAL(clicked(QPieSlice*)), this, SLOT(ClickedSector(QPieSlice*)));

    slice_tcp = new QPieSlice();
    slice_tcp->setLabel("TCP");
    slice_tcp->setValue(tcp_v.size());
    slice_tcp->setColor(QColor(228,255,119,100));


    slice_udp = new QPieSlice();
    slice_udp->setLabel("UDP");
    slice_udp->setValue(udp_v.size());
    slice_udp->setColor(QColor(255,218,185));


    slice_icmp = new QPieSlice();
    slice_icmp->setLabel("ICMP");
    slice_icmp->setValue(icmp_v.size());
    slice_icmp->setColor(QColor(114,238,144));

    m_pPieSeries->clear();
    m_pPieSeries->append(slice_tcp);
    m_pPieSeries->append(slice_udp);
    m_pPieSeries->append(slice_icmp);

    Visualize();

}

Shark::~Shark()
{
    delete ui;
    int size = packages.size();
    for (int i = 0; i < size; i++) {
        free((char*)(packages[i].pkt_content));
        packages[i].pkt_content = NULL;
    }
    QVector<Package>().swap(packages);
    if (alldevs != NULL)
        pcap_freealldevs(alldevs);
    if (adhandle != NULL)
        pcap_close(adhandle);
}

void Shark::showDevices()
{
    ui->comboBox->clear();
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        ui->comboBox->addItem("ERROR! Device not found");
        return;
    }
    device_count = 0;
    ui->comboBox->addItem(QString(u8"选择设备"));
    for (d = alldevs; d != NULL; d = d->next, device_count++)
        ui->comboBox->addItem(QString(d->name) + QString("  ") + QString(d->description));
}

// 选择设备，下拉，槽
void Shark::on_comboBox_currentIndexChanged(int index)
{
    if (index <= 0 || index > device_count)
    {
        d = NULL;
        return;
    }
    int i = 1;
    for (d = alldevs; i < index; i++, d = d->next);
    qDebug() << d->description;
}

// // 设置过滤
//int Shark::setFilter()
//{
//    QString str = "";
//    bpf_u_int32 netmask;
//    struct bpf_program fp;
//    if(d->addresses != NULL)
//        netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
//    else
//        netmask = 0xffffff;

//    qDebug()<<"filter rules: "<<str;
//    if(pcap_compile(adhandle, &fp, str.toLatin1().data(), 1, netmask) < 0)
//    {
//        qDebug()<<" compile ERROR!";
//        return -1;
//    }
//    if(pcap_setfilter(adhandle, &fp) < 0)
//    {
//        qDebug()<<" setFilter ERROR!";
//        return -2;
//    }
//    return 0;
//}

//打开设备
int Shark::openDevice()
{
    if (d == NULL)
        return -1;

    qDebug()<<"selected device: "<<d->name;
    adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

    if (adhandle == NULL)
        return -2;
    statusBar()->showMessage(d->name);
    // 设置过滤器
//    if(setFilter() < 0)
//        return -3;
    pcap_freealldevs(alldevs);
    return 0;
}


//开始按钮
void Shark::on_pushButton_clicked()
{
    int rec;
    if (btnFlag == 0)
    {
        //界面初始化
        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        ui->treeWidget->clear();
        // 清空保存的包
        int size = packages.size();
        for (int i = 0; i < size; i++) {
            free((char*)(packages[i].pkt_content));
            packages[i].pkt_content = NULL;
        }
        QVector<Package>().swap(packages);
        packageCount = 0;

        //清空原有规则
        while (rules.size() != 0) {
            delete[] rules[rules.size() - 1];
            rules.pop_back();
        }


        //导入规则
        if(!setRules())
        {
            statusBar()->showMessage(u8"规则导入失败");
            return;
        }

        //debug 输出规则
        for(int i = 0; i < rules.size(); i++)
        {
            for(int j = 0; j < 7; j++)
                qDebug()<<rules[i][j];
            qDebug()<<"";
        }

        //打开日志文件
        log_file.open("log.txt",std::ios::app);
        if(!log_file.is_open())
        {
            statusBar()->showMessage(u8"log文件打开失败");
            return;
        }


        rec = openDevice();
        if (rec == -1)
            statusBar()->showMessage(u8"请选择正确的设备");
        if (rec != 0)
            return;

        //弹出之前保存的包
        while (tcp_v.size() != 0) {
            tcp_v.pop_back();
        }
        while (udp_v.size() != 0) {
            udp_v.pop_back();
        }
        while (icmp_v.size() != 0) {
            icmp_v.pop_back();
        }

        //清空map
        for(auto iter = map.begin(); iter !=map.end(); iter++){
            for(int i = 0; i < iter.value().size(); i++)
            {
                while(iter.value().size()!=0){
                    iter.value().pop_back();
                }
            }
        }
        map.clear();

        now_view = "";
        //设置饼图显示
        slice_tcp->setValue(tcp_v.size());
        slice_udp->setValue(udp_v.size());
        slice_icmp->setValue(icmp_v.size());

        slice_tcp->setLabel("TCP");
        slice_udp->setLabel("UDP");
        slice_icmp->setLabel("ICMP");
        slice_tcp->setLabelVisible(false);
        slice_udp->setLabelVisible(false);
        slice_icmp->setLabelVisible(false);
        Visualize();

        log_file <<"\n------------------------\n";


        //多线程
        for(int i = 0; i < threads.size(); i++)
        {
            qDebug()<<"Thread: "<<QString::number(i)<<" strat";
            threads[i]->setHandel(adhandle);
            threads[i]->setFlag(1);
            threads[i]->start();
        }

//        //单个线程
//        thread->setHandel(adhandle);
//        thread->setFlag(1);
//        thread->start();

        //过滤
//        ui->checkBox_ARP->setEnabled(false);
//        ui->checkBox_TCP->setEnabled(false);
//        ui->checkBox_ICMP->setEnabled(false);
//        ui->checkBox_UDP->setEnabled(false);

        ui->lineEdit->setEnabled(false);
        ui->comboBox->setEnabled(false);
        ui->check_mode->setEnabled(false);
        ui->pushButton->setText(u8"停止");
        btnFlag = 1;
    }
    else if (btnFlag == 1)
    {

        //多线程停止
        for(int i = 0; i < threads.size(); i++)
        {
            qDebug()<<"Thread: "<<QString::number(i)<<" quit";
            threads[i]->setFlag(0);
            threads[i]->quit();
            threads[i]->wait();
        }

//        //单个线程停止
//        thread->setFlag(0);
//        thread->quit();
//        thread->wait();

        pcap_close(adhandle);   //关闭会话，释放资源
        adhandle = NULL;

        //关闭文件
        log_file.close();

        showDevices();
        ui->pushButton->setText(u8"开始");
        ui->lineEdit->setEnabled(true);
        ui->comboBox->setEnabled(true);
        ui->check_mode->setEnabled(true);
        //过滤
//        ui->checkBox_ARP->setEnabled(true);
//        ui->checkBox_TCP->setEnabled(true);
//        ui->checkBox_ICMP->setEnabled(true);
//        ui->checkBox_UDP->setEnabled(true);

        statusBar()->showMessage("");
        btnFlag = 0;
    }

}

//接收数据，处理数据
void Shark::handleMessage(Package data)
{

    QString type = data.getPackageType();

    // 颜色设置
    QColor color;
    if (type == "TCP") {
        color = QColor(228, 255, 119, 100);
    }
    else if (type == "ICMP") {
        color = QColor(144, 238, 144);
    }
    else if (type == "ARP") {
        color = QColor(250, 240, 215);
    }
    else if (type == "DNS") {
        color = QColor(218, 238, 255);
    }
    else if (type == "TLS" || type == "SSL") {
        color = QColor(210, 149, 210);
    }
    else {
        color = QColor(255, 218, 185);
    }


    //判断是否要记录
    int flag = -1;

    //可视化处理，规则判定
    for(int i=0;i<rules.size();i++){
        QString sip,sport,derection,dip,dport,ruletype,msg;
        sip = rules[i][0];
        sport= rules[i][1];
        derection= rules[i][2];
        dip = rules[i][3];
        dport= rules[i][4];
        ruletype= rules[i][5];
        msg= rules[i][6];

        if(type != ruletype && ruletype != "any")
            continue;

        QString ip_s = data.getSource();
        QString ip_d = data.getDestination();

        if(type == "TCP"){
            //获得TCP包
            const u_char* package = data.pkt_content + 14;
            package += Package::get_ip_HeaderLength(package).toInt();

            //获取端口
            QString port_s = Package::get_tcp_SourcePort(package);
            QString port_d = Package::get_tcp_DestinationPort(package);
            if((ip_s == sip && ip_d == dip)||(ip_s == sip && dip == "any")||(sip == "any" && ip_d == dip)||(sip == "any" && dip == "any"))
            {
                if((port_s == sport && port_d == dport)||(port_s == sport && dport == "any")||(sport == "any" && port_d == dport)||(sport == "any" && dport == "any"))
                {
                    tcp_v.push_back(new int[2]{packageCount, i});
                    flag = i;
                }
            }
        }
        //------------------------------------------------------------------------
        else if(type == "ICMP"){
            QString psip = data.getSource();
            QString pdip = data.getDestination();
            if((ip_s == sip && ip_d == dip)||(ip_s == sip && dip == "any")||(sip == "any" && ip_d == dip)||(sip == "any" && dip == "any"))
            {
                icmp_v.push_back(new int[2]{packageCount, i});
                flag = i;
            }

        }
        //---------------------------------------------------------------------------
        else if(type == "UDP"){
            const u_char* package = data.pkt_content + 14;
            package += Package::get_ip_HeaderLength(package).toInt();

            //获取端口
            QString port_s = Package::get_udp_SourcePort(package);
            QString port_d = Package::get_udp_DestinationPort(package);
            if((ip_s == sip && ip_d == dip)||(ip_s == sip && dip == "any")||(sip == "any" && ip_d == dip)||(sip == "any" && dip == "any"))
            {
                if((port_s == sport && port_d == dport)||(port_s == sport && dport == "any")||(sport == "any" && port_d == dport)||(sport == "any" && dport == "any"))
                {
                    udp_v.push_back(new int[2]{packageCount, i});
                    flag = i;
                }
            }

        }
        else{

        }

     }

    if(flag != -1||ui->check_mode->isChecked())
    {
        ui->tableWidget->insertRow(packageCount);
        //插入数据
        ui->tableWidget->setItem(packageCount, 0, new QTableWidgetItem(QString::number(packageCount + 1)));
        ui->tableWidget->setItem(packageCount, 1, new QTableWidgetItem(data.getTimeStamp()));
        ui->tableWidget->setItem(packageCount, 2, new QTableWidgetItem(data.getSource()));
        ui->tableWidget->setItem(packageCount, 3, new QTableWidgetItem(data.getDestination()));
        ui->tableWidget->setItem(packageCount, 4, new QTableWidgetItem(type));
        ui->tableWidget->setItem(packageCount, 5, new QTableWidgetItem(data.getDataLength()));
        ui->tableWidget->setItem(packageCount, 6, new QTableWidgetItem(data.getInfo()));
        for (int i = 0; i < 7; i++) {
            ui->tableWidget->item(packageCount, i)->setBackground(color);
        }
        qDebug()<<QString::number(packageCount)<<" "<<data.getTimeStamp()<<" "<<data.getSource()
               <<data.getDestination()<<" "<<type<<" "<<data.getDataLength()<<" "<<data.getInfo();


        //保存这个数据包
        packages.push_back(data);

        //流量统计
        add_to_map(data.getSource(), data.getDestination(),packageCount + 1, flag);
//        print_map(map);
        show_package_count();

        packageCount++;

        if(selectRow == -1)
            ui->tableWidget->scrollToBottom();

        if(flag != -1)
        {
            QString log = QString::number(packageCount + 1) + " " + data.getSource() + " -> " + data.getDestination() +" "+ rules[flag][6];
            QString info = QString::number(packageCount) + " " + data.getTimeStamp() + " " + data.getSource()
                                                       + data.getDestination() + " " + type + " " + data.getDataLength() + " " + data.getInfo();
            log_file << log.toStdString() << "  info: " << info.toStdString() << std::endl;

            Visualize();
            if(now_view == "TCP")
                show_tcp();
            if(now_view == "UDP")
                show_udp();
            if(now_view == "ICMP")
                show_icmp();
        }

    }

}


//------------------------------------------------------------------------------------------

QString Shark::view_eth()
{
    QString tree;
    const u_char* data = packages[selectRow].pkt_content;
    QString srcMac = Package::get_eth_Src(data);
    QString desMac = Package::get_eth_Des(data);
    QString type = Package::get_eth_Type(data);
    tree = "Ethernet , Src: " +srcMac + ", Dst: " + desMac;
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);
    item->setBackground(0,QBrush(QColor(229,229,229)));
    ui->treeWidget->addTopLevelItem(item);

    item->addChild(new QTreeWidgetItem(QStringList()<<"Destination: " + desMac));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Source: " + srcMac));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + type));

    return type;
}

QString Shark::view_ip(const u_char* data, int &headerLength)
{
    QString version = Package::get_ip_Version(data);
    QString protocol = Package::get_ip_Protocol(data);
    QString hlen = Package::get_ip_HeaderLength(data);
    headerLength = hlen.toInt();
    QString srcIP = Package::get_ip_Source(data);
    QString desIP = Package::get_ip_Destination(data);

    QString flags = Package::get_ip_Flags(data);
    QString RB = Package::get_ip_Flags_RB(data);
    QString DF = Package::get_ip_Flags_DF(data);
    QString MF = Package::get_ip_Flags_MF(data);
    if(DF == "Set")
        flags += " (Don't Fragment)";

    QString tree = "Internet Protocol Version "+version+", Src: " +srcIP + ", Dst: " + desIP;
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);
    item->setBackground(0,QBrush(QColor(229,229,229)));
    ui->treeWidget->addTopLevelItem(item);

    item->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + version));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: " + hlen + " (bytes)"));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Differentiated Services Field: : " + Package::get_ip_DifferentiatedServicesField(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Total Length: " + Package::get_ip_TotalLength(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Identificiation: " + Package::get_ip_Identification(data)));

    QTreeWidgetItem* f = new QTreeWidgetItem(QStringList()<<"Flags: " + flags);
    item->addChild(f);
    f->addChild(new QTreeWidgetItem(QStringList()<<"Reserved bit: " + RB));
    f->addChild(new QTreeWidgetItem(QStringList()<<"Don't fragment: " + DF));
    f->addChild(new QTreeWidgetItem(QStringList()<<"More fragments: " + MF));

    item->addChild(new QTreeWidgetItem(QStringList()<<"Fragment offset: " + Package::get_ip_FragmentOffset(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Time to live: " + Package::get_ip_TimeToLive(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: " + protocol));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum: " + Package::get_ip_HeaderChecksum(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Source: " + srcIP));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Destination: " + desIP));

    return protocol;
}

QString Shark::view_icmp(const u_char* data)
{
    QString tree = "Internet Control Message Protocol";
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);
    item->setBackground(0,QBrush(QColor(229,229,229)));
    ui->treeWidget->addTopLevelItem(item);

    QString type = Package::get_icmp_Type(data);
    QString code = Package::get_icmp_Code(data);
    QString checksum = Package::get_icmp_Checksum(data);
//    qDebug()<<type;
    if(type == "0" || type == "8")
    {
        if(type == "0")
            type += " (Echo (ping) reply)";
        if(type == "8")
            type += " (Echo (ping) request)";
        int identifer = Package::get_icmp_Identifier(data).toInt();
        int seq = Package::get_icmp_SequenceNumber(data).toInt();

        item->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + type));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Code: " + code));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Checksum: " + checksum));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Identifier (BE): 0x" + QString("%1").arg(identifer, 4, 16, QChar('0'))));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Identifier (LE): 0x" + QString("%1").arg(ntohs(identifer), 4, 16, QChar('0'))));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Sequence number (BE): 0x" + QString("%1").arg(seq, 4, 16, QChar('0'))));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Sequence number (LE): 0x" + QString("%1").arg(ntohs(seq), 4, 16, QChar('0'))));
    }
    return "";
}

QString Shark::view_tcp(const u_char *data)
{
    QString srcPort = Package::get_tcp_SourcePort(data);
    QString desPort = Package::get_tcp_DestinationPort(data);
    QString seq = Package::get_tcp_SequenceNumber(data);
    QString ack = Package::get_tcp_AcknowledgmentNumver(data);
    QString flags = Package::get_tcp_Flags(data);
    flags += " (" + Package::get_tcp_Flags_info((TCP_HEADER*)data) + ")";

    int len = Package::get_ip_TotalLength(packages[selectRow].pkt_content + 14).toInt() - Package::get_ip_HeaderLength(packages[selectRow].pkt_content + 14).toInt() - Package::get_tcp_HeaderLength(data).toInt();
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:"+srcPort
                                                + ", Dst Port: "+desPort+" Seq: "+seq+", Ack: "+ack + " Len: " + QString::number(len));
    item->setBackground(0,QBrush(QColor(229,229,229)));
    ui->treeWidget->addTopLevelItem(item);

    item->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: " + srcPort));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: " + desPort));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: " + seq));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: " + ack));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Header Length: " + Package::get_tcp_HeaderLength(data) + " bytes"));

    QTreeWidgetItem* Flags = new QTreeWidgetItem(QStringList()<<"Flags: " + flags);
    item->addChild(Flags);
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Reserved: " + Package::get_tcp_Flags_Reserved(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Nonce: " + Package::get_tcp_Flags_Nonce(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Congestion Window Reduced: " + Package::get_tcp_Flags_CWR(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"ECN-Echo: " + Package::get_tcp_Flags_ECN(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Urgent: " + Package::get_tcp_Flags_Urgent(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment: " + Package::get_tcp_Flags_ACK(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Push: " + Package::get_tcp_Flags_Push(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Reset: " + Package::get_tcp_Flags_Reset(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Syn: " + Package::get_tcp_Flags_SYN(data)));
    Flags->addChild(new QTreeWidgetItem(QStringList()<<"Fin: " + Package::get_tcp_Flags_FIN(data)));

    item->addChild(new QTreeWidgetItem(QStringList()<<"Window size value: " + Package::get_tcp_WindowSizeValue(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Checksum: " + Package::get_tcp_Checksum(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Urgent pointer: " + Package::get_tcp_UrgentPointer(data)));

    return "";
}

QString Shark::view_udp(const u_char *data)
{
    QString srcPort = Package::get_udp_SourcePort(data);
    QString desPort = Package::get_udp_DestinationPort(data);
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port: "+ srcPort +", Dst Port: "+desPort);
    item->setBackground(0,QBrush(QColor(229,229,229)));
    ui->treeWidget->addTopLevelItem(item);

    item->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: " + srcPort));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: " + desPort));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + Package::get_udp_Length(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Checksum: " + Package::get_udp_Checksum(data)));

    return "";
}

QString Shark::view_arp(const u_char *data)
{
    QString op = Package::get_arp_Opcode(data);
    QString tree = "Address Resolution Protocol (" + op +")";

    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);
    item->setBackground(0,QBrush(QColor(229,229,229)));

    ui->treeWidget->addTopLevelItem(item);
    item->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type: " + Package::get_arp_HardwareType(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type: " + Package::get_arp_ProtocolType(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size: " + Package::get_arp_HardwareSize(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size: " + Package::get_arp_ProtocolSize(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Opcode: " + Package::get_arp_Opcode(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address: " + Package::get_arp_SenderMac(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address: " +Package::get_arp_SenderIp(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address: " + Package::get_arp_TargetMac(data)));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address: " + Package::get_arp_TargetIp(data)));
    return "";
}

// 点击行
void Shark::on_tableWidget_cellClicked(int row, int column)
{
    now_view = "";

    if(row == selectRow || row < 0 || selectRow > packageCount){
        selectRow = -1;
        return;
    }

    ui->treeWidget->clear();
    selectRow = row;

    qDebug()<<"selected row "<<row;
    QString type = view_eth();

    //IP
    if(type == "IP (0x0800)")
    {
        int ipHeaderLen;
        QString protocol = view_ip(packages[selectRow].pkt_content + 14, ipHeaderLen);

//        qDebug()<<" len: "<<ipHeaderLen;
//        qDebug()<<protocol;

        if(protocol == "ICMP")
            view_icmp(packages[selectRow].pkt_content + 14 + ipHeaderLen);
        else if (protocol == "TCP") {
            view_tcp(packages[selectRow].pkt_content + 14 + ipHeaderLen);
        }
        else if (protocol == "UDP") {
            view_udp(packages[selectRow].pkt_content + 14 + ipHeaderLen);
        }
    }

    // arp
    if(type == "ARP (0x0806)")
    {
        view_arp(packages[selectRow].pkt_content + 14);
    }
}

//导入规则
bool Shark::setRules()
{
//    return true;
    //rules
    QString filename = ui->lineEdit->text();
    qDebug()<<filename;
    QString aline;
    QString sip,sport,derection,dip,dport,type,msg;
    QFile file(filename);

    bool open = file.open(QIODevice::ReadOnly);
    if(open){
        while(!file.atEnd()){
            aline = file.readLine();
//            qDebug()<<aline;
            //int alineLength=aline.size();

            if(aline!="\r\n"){
                QStringList strlist=aline.split(' ');

                int listLength=strlist.size();
                if(listLength != 7){
                    qDebug()<<"rule less";
                    return false;
                }
                sip=strlist[0];
//                if(!isip(sip)){
//                    qDebug()<<"SIP error";
//                    return false;
//                }
                sport=strlist[1];
//                if(!isport(sport)){
//                    qDebug()<<"sport error";
//                    return false;
//                }
                derection= strlist[2];
//                if(!isderection(derection)){
//                    qDebug()<<"op error";
//                    return false;
//                }
                dip=strlist[3];
//                if(!isip(dip)){
//                    qDebug()<<"DIP error";
//                    return false;
//                }
                dport=strlist[4];
//                if(! isport(sport)){
//                    qDebug()<<"dport error";
//                    return false;
//                }
                type=strlist[5];
                msg=strlist[6];
                if(msg[msg.size() - 1] == "\n")
                    msg[msg.size() - 1] = ' ';

                //方向
                if(derection == "<-")
                {
                    QString temp = sip;
                    sip = dip;
                    dip = temp;
                    temp = sport;
                    sport = dport;
                    dport = sport;
                }

                QString *str7= new QString[7]{sip,sport,derection,dip,dport,type,msg};

                //保存规则
                rules.push_back(str7);

                //双向
                if(derection == "<>")
                {
                    str7= new QString[7]{dip,dport,derection,sip,sport,type,msg};
                    rules.push_back(str7);
                }


                //qDebug()<<rules;

            }else{
                qDebug()<<"have free line";
            }
        }
        file.close();
        return true;
    }
    else{
        qDebug()<<"file open error";
    }
    return false;
}

void Shark::Visualize()
{
    //更新扇形图数据
    slice_tcp->setValue(tcp_v.size());
    slice_udp->setValue(udp_v.size());
    slice_icmp->setValue(icmp_v.size());

    double sum = tcp_v.size() + udp_v.size() + icmp_v.size();

    if(tcp_v.size())
        slice_tcp->setLabel("TCP "+ QString::number((tcp_v.size() / sum) * 100, 'g', 4) + "%");
    if(udp_v.size())
        slice_udp->setLabel("UDP "+ QString::number((udp_v.size() / sum) * 100, 'g', 4) + "%");
    if(icmp_v.size())
        slice_icmp->setLabel("ICMP "+ QString::number((icmp_v.size() / sum) * 100, 'g', 4) + "%");

    if(tcp_v.size())
        slice_tcp->setLabelVisible(true);

    if(udp_v.size())
        slice_udp->setLabelVisible(true);

    if(icmp_v.size())
        slice_icmp->setLabelVisible(true);

    //设置按钮
    ui->show_tcp->setText(QString::number(tcp_v.size()));
    ui->show_udp->setText(QString::number(udp_v.size()));
    ui->show_icmp->setText(QString::number(icmp_v.size()));
}


void Shark::show_tcp()
{
    ui->treeWidget->clear();

    for(int i = 0; i < tcp_v.size(); i++)
    {
        //获取IP包
        const u_char *data = packages[tcp_v[i][0]].pkt_content + 14;
        QString srcIP = Package::get_ip_Source(data);
        QString desIP = Package::get_ip_Destination(data);
        QString time = packages[tcp_v[i][0]].getTimeStamp();
        //获取TCP包
        data += Package::get_ip_HeaderLength(data).toInt();
        QString port_s = Package::get_tcp_SourcePort(data);
        QString port_d = Package::get_tcp_DestinationPort(data);

        QString tree = QString::number(tcp_v[i][0] + 1) +" " + time + " "
                +srcIP + ":" + port_s + "  \t\t"+ desIP + ":" + port_d + "  \t\t"+ rules[tcp_v[i][1]][6];
        QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);

        ui->treeWidget->addTopLevelItem(item);
    }
}

void Shark::show_udp()
{
    ui->treeWidget->clear();

    for(int i = 0; i < udp_v.size(); i++)
    {
        //获取IP包
        const u_char *data = packages[udp_v[i][0]].pkt_content + 14;
        QString srcIP = Package::get_ip_Source(data);
        QString desIP = Package::get_ip_Destination(data);
        QString time = packages[udp_v[i][0]].getTimeStamp();
        //获取UDP包
        data += Package::get_ip_HeaderLength(data).toInt();
        QString port_s = Package::get_udp_SourcePort(data);
        QString port_d = Package::get_udp_DestinationPort(data);

        QString tree = QString::number(udp_v[i][0] + 1) +" " + time + " "
                +srcIP + ":" + port_s + "  \t\t"+ desIP + ":" + port_d + "  \t\t"+ rules[udp_v[i][1]][6];
        QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);

        ui->treeWidget->addTopLevelItem(item);
    }
}

void Shark::show_icmp()
{
    ui->treeWidget->clear();

    for(int i = 0; i < icmp_v.size(); i++)
    {
        const u_char *data = packages[icmp_v[i][0]].pkt_content + 14;
        QString srcIP = Package::get_ip_Source(data);
        QString desIP = Package::get_ip_Destination(data);
        QString time = packages[icmp_v[i][0]].getTimeStamp();
        QString tree = QString::number(icmp_v[i][0] + 1) +" " + time + " "+srcIP + "  \t\t" + desIP + "  \t\t" + rules[icmp_v[i][1]][6];
        QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);

        ui->treeWidget->addTopLevelItem(item);
    }
}

//显示过滤到的TCP包
void Shark::on_show_tcp_clicked()
{
    now_view = "TCP";
    show_tcp();
}

//显示UDP包
void Shark::on_show_udp_clicked()
{
    now_view = "UDP";
    show_udp();
}

//显示ICMP包
void Shark::on_show_icmp_clicked()
{
    now_view = "ICMP";
    show_icmp();
}

//流量统计
bool Shark::add_to_map(QString sip, QString dip,int num, int rule){

    QString str = dip +" "+ sip;
    if(map[str].size() != 0)
    {
        map[str].push_back(new QString[4]{sip, dip, QString::number(num), QString::number(rule)});
        return true;
    }

    str = sip +" "+ dip;
    if(map[str].size() != 0)
    {
        map[str].push_back(new QString[4]{sip, dip, QString::number(num), QString::number(rule)});
        return true;
    }

    map[str].push_back(new QString[4]{sip, dip, QString::number(num), QString::number(rule)});
    qDebug()<<"success addtomap";
    return false;
}

void Shark::print_map(QMap<QString, int> &map){
    if( map.isEmpty()){
        qDebug()<<"map is empty";
    }
    else{
        QMap<QString, int>::iterator iter;
        for(iter=map.begin(); iter !=map.end(); iter++){
            qDebug()<<iter.key()<<"  packege count:"<<iter.value();
        }
    }
}

void Shark::show_package_count(){
    ui->count->clear();

    if( map.isEmpty()){
        qDebug()<<"map is empty";
    }
    else{
        for(auto iter = map.begin(); iter !=map.end(); iter++){
            if(iter.value().size() == 0)
                continue;
            QString ip1 = iter.value()[0][0];
//            qDebug()<<ip1;
            QString ip2 = iter.value()[0][1];
//            qDebug()<<ip2;
            QString tree = ip1 + "\t" + ip2 + "\tpackage count:" + QString::number(iter.value().size());
            QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);
            item->setBackground(0,QBrush(QColor(229,229,229)));
            ui->count->addTopLevelItem(item);
            for(int i = 0; i < iter.value().size(); i++)
            {
                QString info = iter.value()[i][2] + " " + iter.value()[i][0] + "  \t=>\t" + iter.value()[i][1];
                int rule = iter.value()[i][3].toInt();
                if(rule != -1)
                    info += "\t" + rules[rule][6];
                item->addChild(new QTreeWidgetItem(QStringList()<<info));
            }
//            qDebug()<<iter.key()<<"  packege count:"<<iter.value().size();
        }
    }

}

//void Shark::show_package_count(){
//    ui->count->clear();

//    if( map.isEmpty()){
//        qDebug()<<"map is empty";
//    }
//    else{
//        QMap<QString, int>::iterator iter;
//        for(iter=map.begin(); iter !=map.end(); iter++){


//            QString tree = iter.key()+"  package count:"+QString::number(iter.value());
//            QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<tree);
//            ui->count->addTopLevelItem(item);

//            qDebug()<<iter.key()<<"  packege count:"<<iter.value();
//        }
//    }

//}








# LittleShark
简单实现类似wireshark的可以对包进行分析的工具
* 可以对部分TCP包、ICMP包、UDP包进行分析，可以实现多线程抓包（需要优化改进）
* 可以根据规则对包进行过滤，并进行分析和导出
* 可以统计两个IP之间通信的包的个数以及类型

---
后续还有很多地方需要实现和优化

---
使用前需要配置winpcap开发包位置，以及其他一些配

---

参考 `https://github.com/djh-sudo/Network-capture`

### 抓包分析
![抓包分析](https://github.com/ky0ma/Network_Capture/blob/main/img/%E6%8A%93%E5%8C%85%E5%88%86%E6%9E%90.png)

### 流量统计
![流量统计](https://github.com/ky0ma/Network_Capture/blob/main/img/%E6%B5%81%E9%87%8F%E7%BB%9F%E8%AE%A1.png)


# LittleShark
简单实现类似wireshark的可以对包进行分析的工具
* 可以对部分TCP包、ICMP包、UDP包进行分析，可以实现多线程抓包（需要优化改进）
* 可以根据规则对包进行过滤，并进行分析和导出
* 可以统计两个IP之间通信的包的个数以及类型

---
使用前需要配置winpcap开发包位置，以及其他一些配

---

参考 `https://github.com/djh-sudo/Network-capture`

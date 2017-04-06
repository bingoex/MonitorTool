# MonitorTool
一个系统监控参数脚本<br\>
a script that report the linux system parameters<br>
参数详情可查看[本人博客](http://blog.csdn.net/b2222505)
监控数据涉及：
- cpu
- 内存
- swap
- 共享内存
- 磁盘(磁盘使用率、io效率)
- 网络(tcp\udp\ip\icmp\网卡)
- 文件句柄

使用方式：
- 重写reportHandle方法，增加上报逻辑
- 增加crontab
```shell
*/1 * * * * /your/path/ServerReport.py &>/dev/null
```



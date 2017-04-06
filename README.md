# MonitorTool
## 一个系统参数监控脚本
参数详情可查看[本人博客](http://blog.csdn.net/b2222505)<br>
监控数据涉及：
- cpu
- 内存
- swap
- 共享内存
- 磁盘(磁盘使用率、io效率)
- 网络(tcp\udp\ip\icmp\网卡)
- 文件句柄

## 使用方式：
- 重写reportHandle方法，增加上报逻辑(默认只输出)
- 增加crontab,定时跑脚本获取数据
```shell
*/1 * * * * /your/path/ServerReport.py &>/dev/null
```



#!/usr/bin/env python
#-*-coding=utf-8-*-
#
# Reprot Server Basic Information

from __future__ import division
import math
import os
import re
import sys
import traceback
from time import time, sleep

os.environ['PATH'] += ":/sbin:/usr/sbin"
version_num = "1.0"

class BaseInfo(object):
    def __init__(self):
        # a map dict that containt a lot of id and the system paramters mean of the id 
        self.reportid = { 
                #cpu usage
                #cpu:各个CPU平均使用情况；cpu0：CPU0使用情况
                'cpu':71123, 'cpu0':71124, 'cpu1':71125, 
                'cpu2':71126, 'cpu3':71127, 'cpu4':71128,
                'cpu5':71129, 'cpu6':71130, 'cpu7':71131, 
                'cpu8':213059, 'cpu9':213060, 'cpu10':213061,
                'cpu11':213062, 'cpu12':213063, 'cpu13':213064, 
                'cpu14':213065, 'cpu15':213066,'cpu16':333546,
                'cpu17':333547,'cpu18':333548,'cpu19':333549,
                'cpu20':333550,'cpu21':333551,'cpu22':333552,
                'cpu23':333553,'cpu24':333554,'cpu25':333555,
                'cpu26':333556,'cpu27':333557,'cpu28':333558,
                'cpu29':333559,'cpu30':333560,'cpu31':333561,
                'cpu32':2550519, 'cpu33':2550520, 'cpu34':2550521,
                'cpu35':2550522, 'cpu36':2550523, 'cpu37':2550524, 
                'cpu38':2550525, 'cpu39':2550526, 'cpu40':2550527, 
                'cpu41':2550528, 'cpu42':2550529, 'cpu43':2550530, 
                'cpu44':2550531, 'cpu45':2550532, 'cpu46':2550533, 'cpu47':2550534,
                #top_core_usage
                #CPU单一进程利用率最高值
                'top_core_usage':177187,
                #cpu load
                'cpu_load_1':499334,'cpu_load_5':499335,'cpu_load_15':499336,
                #memory usage
                #SwapTotal:总swap空间大小（mb）
                'mem_used':71132,'mem_free':71133, 'SwapTotal':2377135, 'SwapFree':2377136,
                #shm usage
                #shm_use：机器共享内存总量（KB）；shm_num：共享内存块数；/dev/shm：/dev/shm下文件总大小（POSIX）
                'shm_use':71151,'shm_num':71152,'/dev/shm':404594,
                #swap usage
                #swap_in：磁盘交换到内存中
                'swap_in':177091,'swap_out':177092,
                #hard disk usage
                #/:磁盘使用率（％）
                '/':71134, '/usr/local':71135, '/data':71136, '/data1':71137, 
                '/data2':71138, '/data3':71139, '/data4':71140, '/ssd/data':71155, 
                '/ssd/data1':71156, '/ssd/data2':71157, '/ssd/data3':71158, '/ssd/data4':71159,
                '/ssd/data5':71160, '/ssd/data6':71161, '/ssd/data7':71162, '/ssd/data8':71163,
                #hard disk io usage
                #sda_rio：sda每秒读请求（次／秒）；sda_wio：sda每秒写请求
                #sda_rsect：sda磁盘io读（KB／s）；sda_wsect：sda磁盘io写
                #sda_await：sda平均每次操作的等待时间（微秒）
                #sda_svctm：sda平均每次IO操作的服务时间（微秒）
                'sda_rio':71147,'sda_wio':71148,'sda_rsect':71145,'sda_wsect':71146,'sda_await':71149,'sda_svctm':71150,
                'sdb_rio':888438,'sdb_wio':888439,'sdb_rsect':888440,'sdb_wsect':888441,'sdb_await':888442,'sdb_svctm':888443,
                'sdc_rio':888444,'sdc_wio':888445,'sdc_rsect':888446,'sdc_wsect':888447,'sdc_await':888448,'sdc_svctm':888449,
                'sdd_rio':888450,'sdd_wio':888451,'sdd_rsect':888452,'sdd_wsect':888453,'sdd_await':888454,'sdd_svctm':888455,
                'sde_rio':888456,'sde_wio':888457,'sde_rsect':888458,'sde_wsect':888459,'sde_await':888460,'sde_svctm':888461,
                'sdf_rio':888462,'sdf_wio':888463,'sdf_rsect':888464,'sdf_wsect':888465,'sdf_await':888466,'sdf_svctm':888467,
                'sdg_rio':888468,'sdg_wio':888469,'sdg_rsect':888470,'sdg_wsect':888471,'sdg_await':888472,'sdg_svctm':888473,
        'sdh_rio':888474,'sdh_wio':888475,'sdh_rsect':888476,'sdh_wsect':888477,'sdh_await':888478,'sdh_svctm':888479,
                        'sdi_rio':888480,'sdi_wio':888481,'sdi_rsect':888482,'sdi_wsect':888483,'sdi_await':888484,'sdi_svctm':888485,
                        'sdj_rio':888486,'sdj_wio':888487,'sdj_rsect':888488,'sdj_wsect':888489,'sdj_await':888490,'sdj_svctm':888491,
                        'sdk_rio':888492,'sdk_wio':888493,'sdk_rsect':888494,'sdk_wsect':888495,'sdk_await':888496,'sdk_svctm':888497,
                        'sdl_rio':888498,'sdl_wio':888499,'sdl_rsect':888500,'sdl_wsect':888501,'sdl_await':888502,'sdl_svctm':888503,
                        'sdm_rio':888504,'sdm_wio':888505,'sdm_rsect':888506,'sdm_wsect':888507,'sdm_await':888508,'sdm_svctm':888509,
                        'sdn_rio':888510,'sdn_wio':888511,'sdn_rsect':888512,'sdn_wsect':888513,'sdn_await':888514,'sdn_svctm':888515,
                        'sdo_rio':888516,'sdo_wio':888517,'sdo_rsect':888518,'sdo_wsect':888519,'sdo_await':888520,'sdo_svctm':888521,
                        #udp information
                        #InDatagrams:UDP Received(pkg/s)；NoPorts：packets to unknown port received
                        #InErrors：包无法送达应用层（1、收包缓冲区满；2、入包校验失败；3、其他）
                        #OutDatagrams：UDP发包量（pkg／s）；RcvbufErrors：接收缓冲区溢出的包;
                        #SndbufErrors：发包缓冲区溢出的包；UdpInCsumErrors：UDP入包校验失败
                        'InDatagrams':71143,'NoPorts':898358,'InErrors':71144,'OutDatagrams':71142,
                        'RcvbufErrors':898335,'SndbufErrors':898336, 'UdpInCsumErrors':2394144,
                        #tcp information
                        #ActiveOpens：服务器主动连接的TCP轻轻数（每分钟）；PassiveOpens：服务器接收到的TCP请求数
                        #AttemptFails：TCP连接建立时被对方重置（每分钟）；CurrEstab：TCP当前连接数
                        #InSegs：TCP Received（pkg／s）；OutSegs：TCP Send
                        #RetransRatio：当前分钟TCP重传率；RetransSegs：TCP报文重传数（pkg／min）
                        #InErrs：TCP入包错误（pkg／min）NewEstab：TCP连接数变化值（新增或减少）
                        #OutRsts：TCP发送重置包；EstabResets：已建立的连接被重置
                        #TcpInCsumErrors：TCP入包校验失败
                        'ActiveOpens':898560,'PassiveOpens':898485,'AttemptFails':100842,'CurrEstab':11741,'InSegs':898486,'OutSegs':898487,
                        'RetransRatio':898489, 'RetransSegs': 3829253, 'InErrs':898488,'NewEstab':402109, 
                        "OutRsts":3289035, "EstabResets":2389036, 'TcpInCsumErrors':2394145,
                        #file descriptor information
                        #fd_used：已分配句柄数；fd_unuse：已分配未使用句柄数；fd_max：系统最大文件句柄数
                        'fd_used':210737,'fd_unuse':201738,'fd_max':201739,
                        #network speed information
                        #eth0：eth0网卡速来 MB/s
                        'eth0':460901,'eth1':46902,
                        #net device queueing discipline statistics
                        #eth0_qdisc_dropped：eth0发送队列满丢包；
                        #eth0_qdisc_requeues：eth0再入队
                        'eth0_qdisc_dropped':742490, 'eth0_qdisc_requeues':724914,
                        'eth1_qdisc_dropped':427492, 'eth1_qdisc_requeues':497243,
                        #/proc/net/snmp Ip statistics
                        #InReceives：入包综述；InHdrErrors：入包头错误；InDiscards：入包丢包；InDelivers：入包送达上层协议
                        #OutRequests：出包数；OutDiscards：出包丢包；ReasmTimeout：分片重组超时；ReasmReqds：入包需重组；
                        #ReasmOKs：分片重组成功；ReasmFails：分片重组失败；FragOKs：分片成功；FragFails：分片失败；FragCreates：创建分片数
                        'InReceives': 919602, 'InHdrErrors':919603, 'InDiscards':919604, 'InDelivers':919605,
                        'OutRequests':919606, 'OutDiscards':919607, 'ReasmTimeout':919608, 'ReasmReqds':919609,
                        'ReasmOKs':919610, 'ReasmFails':919611,'FragOKs':919612,'FragFails':919613,'FragCreates':919614,
                        #/proc/net/snmp Icmp statistics
                        #InDestUnreachs：收到目标消息不可达
                        #OutDestUnreachs：发送目标不可达消息
                        'InDestUnreachs':3942054, 'OutDestUnreachs':9234055,
                       }

    # report to monitor
    def reportHandle(self, id, value):
        #TODO change to do what you want
        if type(value) == int or type(value) == long:
            print "id:%s value:%i" (str(id).strip(), value)
        elif type(value) == str:
            print "id:%s value:%s" (str(id).strip(), value)
        else:
            print "ReportError: value type error!!!"

class CommProcess(object):
    '''
    基类，每一个功能类都要继承这个基类的方法。
    '''
    def __init__(self,sleepTime):
        self.sleep_time = sleepTime
        self.base_info = BaseInfo()


    def getStatus(self):
        '''
        采集上报的数据，由子类实现。

        返回值
        return_dict = {'key1':v1,'key2':v2,...}
        return_dict = {'key1':[v1,v2,...],'key2':[v1,v2,...],...}
        '''
        pass


    def process(self):
        '''
        通用的处理方法，根据getStatus的返回值（字典）以及self.sleepTime()，做相应的处理，

        返回值
        return_dict = {'key1':v1,'key2':v2,...}
        return_dict = {'key1':[v1,v2,...],'key2':[v1,v2,...],...}
        '''
        result = self.getStatus()
        if self.sleep_time == 0:
            process_dict = result
        elif self.sleep_time > 0:
            sleep(self.sleep_time)
            result2 = self.getStatus()
            # 获取sleepTime时间间隔内的变化值
            if type(result) == dict and type(result2) == dict and len(result) > 0 and len(result2) > 0:
                for key in result2.keys():
                    if type(result2[key]) == list:
                        for i in range(len(result2[key])):
                            try:
                                tmp = long(result2[key][i]) - long(result[key][i])
                            except Exception:
                                print traceback.format_exc()
                                tmp = 0
                            if tmp < 0:
                                #防止溢出
                                result2[key][i] = tmp + 4294967296
                            else:
                                result2[key][i] = tmp
                    else:
                        try:
                            tmp = long(result2[key]) - long(result[key])
                        except Exception:
                            print traceback.format_exc()
                            tmp = 0
                        if tmp < 0:
                            result2[key] = tmp + 4294967296
                        else:
                            result2[key] = tmp

            process_dict = result2

        return process_dict


    def report(self):
        '''
        上报,目前的做法是简单的print
        report_dict = {'key1':v1,'key2':v2}

        无返回值
        '''
        report_data = self.process()
        if len(report_data) > 0:
            for key in report_data.keys():
                if key not in self.base_info.reportid \
                        or report_data[key] == 0:
                            continue
                self.base_info.reportHandle(self.base_info.reportid[key],report_data[key])


class SvrCpuLoad(CommProcess):
    '''get cpu average load'''
    def getStatus(self):
        cmd_get_cpu_load = "/bin/cat /proc/loadavg|awk '{print $1,$2,$3}'"
        cpu_load_list = os.popen(cmd_get_cpu_load).read().split()
        cpu_load_dict = {}
        cpu_load_dict['cpu_load_1'] = long(float(cpu_load_list[0]) * 100)
        cpu_load_dict['cpu_load_5'] = long(float(cpu_load_list[1]) * 100)
        cpu_load_dict['cpu_load_15'] = long(float(cpu_load_list[2]) * 100)
        return cpu_load_dict

class TopCpuUsage(CommProcess):
    '''get top cpu core usage 获取占用cpu最高的进程的cpu消耗百分比'''
    def getStatus(self):
        cmd_get_top_cpu_usage_cmd = '''top -b -n 1 | awk '($1 ~ /[0-9]/){a[$1]=$9}END{max=0; for(i in a){if(max<a[i]){max=a[i]}};print int(max)}' '''
        cmd_get_top_cpu_usage = os.popen(cmd_get_top_cpu_usage_cmd).read()
        return {'top_core_usage': long(cmd_get_top_cpu_usage)}


class SvrCpuUsage(CommProcess):
    '''Get each cpu use information'''
    def getStatus(self):
        fd = open('/proc/stat')
        cpus_info_list = [ l for l in fd.readlines() if l.startswith('cpu') ]
        fd.close()
        cpus_use_dict = {}
        for line in cpus_info_list:
            cpu_list = line.split()
            cpus_use_dict[cpu_list[0]] = cpu_list[1:]

        return cpus_use_dict

    #需作特殊处理 求占比
    def process(self):
        report_dict = {}
        process_dict = super(SvrCpuUsage,self).process()
        for key in process_dict.keys():
            try:
                total = 0.0
                for item in process_dict[key]:
                    total += float(item)
                #cpu usage =  100 * (total-idle)/toal
                report_dict[key] = int(math.ceil(100 * (total-process_dict[key][3])/total))
            except Exception:
                print traceback.format_exc()
                report_dict[key] = 0

        return report_dict


class SvrMemUsage(CommProcess):
    '''
        Get memory usage
    '''
    def getStatus(self):
        fd = open("/proc/meminfo")
        mem_info_list = fd.readlines()
        fd.close()
        mem_use_dict = {}
        for line in mem_info_list:
            tmp = line.split(":")
            try:
                mem_use_dict[tmp[0]] = long(tmp[1].split()[0])
            except Exception:
                print traceback.format_exc()
                mem_use_dict[tmp[0]] = 0

        return mem_use_dict

    #需作特殊处理 free的定义可能不同
    def process(self):
        report_dict = {}
        process_dict = super(SvrMemUsage,self).process()
        if process_dict.has_key('Mapped'):
            report_dict['mem_free'] = long((process_dict['MemFree']+process_dict['Cached']-process_dict['Dirty'] - process_dict['Mapped'])/1024)
        else:
            report_dict['mem_free'] = long(process_dict['MemFree']/1024)
        report_dict['mem_used'] = long(process_dict['MemTotal']/1024) - report_dict['mem_free']
        report_dict['SwapTotal'] = long(process_dict['SwapTotal']/1024)
        report_dict['SwapFree'] = long(process_dict['SwapFree']/1024)

        return report_dict


class SvrShmUsage(CommProcess):
    '''
        Get shm usage
    '''
    def getStatus(self):
        cmd_get_shm_use = "/usr/bin/ipcs -mu|/bin/egrep '^(segments allocated|pages allocated)'"
        fd = os.popen(cmd_get_shm_use)
        shm_list = fd.readlines()
        fd.close()
        shm_use_dict = {}
        for line in shm_list:
            tmp = line.split()
            try:
                shm_use_dict[tmp[0]+tmp[1]] = long(tmp[2])
            except Exception:
                print traceback.format_exc()
                shm_use_dict[tmp[0]+tmp[1]] = 0

        return shm_use_dict

    #需作特殊处理 对数值作额外的处理
    def process(self):
        report_dict = {}
        process_dict = super(SvrShmUsage,self).process()
        report_dict['shm_num'] = process_dict['segmentsallocated']
        report_dict['shm_use'] = long(process_dict['pagesallocated'] * 4 )

        return report_dict


class SvrPosixShm(CommProcess):
    '''
        Get posix shm usage
    '''
    def getStatus(self):
        cmd_get_shm_use = "du -sm /dev/shm"
        fd = os.popen(cmd_get_shm_use)
        shm_list = fd.read().strip().split()
        fd.close()
        posix_shm_dict = {}
        posix_shm_dict['/dev/shm'] = int(shm_list[0])

        return posix_shm_dict

class SvrSwapUsage(CommProcess):
    '''
        Get swap in and out amount
    '''
    def getStatus(self):
        cmd_get_swap_use = "/bin/cat /proc/vmstat|/bin/egrep 'pswpin|pswpout'"
        fd = os.popen(cmd_get_swap_use)
        swap_list = fd.readlines()
        fd.close()
        swap_dict = {}
        for line in swap_list:
            tmp = line.split()
            try:
                swap_dict[tmp[0]] = long(tmp[1])
            except Exception:
                print traceback.format_exc()
                swap_dict[tmp[0]] = 0

        return swap_dict

    #需作特殊处理 对数值作额外的处理 (单位)
    def process(self):
        report_dict = {}
        process_dict = super(SvrSwapUsage,self).process()
        report_dict['swap_in'] = long(process_dict['pswpin']/self.sleep_time)
        report_dict['swap_out'] = long(process_dict['pswpout']/self.sleep_time)

        return report_dict

class SvrHdUsage(CommProcess):
    '''
        Get Hard disk use amount
    '''
    def getStatus(sef):
        cmd_get_hd_use = '/bin/df'
        fd = os.popen(cmd_get_hd_use)
        re_obj = re.compile(r'^/dev/.+\s+(?P<used>\d+)%\s+(?P<mount>.+)')
        hd_use = {}
        for line in fd:
            match = re_obj.search(line)
            if match is not None:
                hd_use[match.groupdict()['mount']] = int(match.groupdict()['used'])
        fd.close()

        return hd_use


class SvrHdIoRatio(CommProcess):
    '''
        Get hard disk IO usage
    '''
    def getStatus(self):
        cmd_get_disk_io = "cat /proc/diskstats |egrep -e '[[:space:]]sd[a-z][[:space:]]'"
        fd = os.popen(cmd_get_disk_io)
        disk_io_list = fd.readlines()
        fd.close()
        disk_io_dict = {}
        if len(disk_io_list) > 0:
            for line in disk_io_list:
                io_list = line.split()
                disk_io_dict[io_list[2]] = io_list[3:]

        return disk_io_dict

    #需作特殊处理 对数值作额外的处理 (单位)
    def process(self):
        report_dict = {}
        process_dict = super(SvrHdIoRatio,self).process()
        for key in process_dict.keys():
            report_dict[key+'_rio'] = long(process_dict[key][0] / 60)
            report_dict[key+'_wio'] = long(process_dict[key][4] / 60)
            report_dict[key+'_rsect'] = long(process_dict[key][2] / 120)
            report_dict[key+'_wsect'] = long(process_dict[key][6] / 120)
            report_dict[key+'_await'] = long((process_dict[key][3]+process_dict[key][7]) * 1000 / (process_dict[key][0]+process_dict[key][4]))
            report_dict[key+'_svctm'] = long(process_dict[key][9] * 1000 / (process_dict[key][0]+process_dict[key][4]))

        return report_dict


class SvrFdInfo(CommProcess):
    '''
        Get file descriptor amount
    '''
    def getStatus(self):
        fd_tmp = open("/proc/sys/fs/file-nr").read().strip().split()
        fd_info = {}
        fd_info['fd_used'] = long(fd_tmp[0])
        fd_info['fd_unuse'] = long(fd_tmp[1])
        fd_info['fd_max'] = long(fd_tmp[2])

        return fd_info


class SvradaptSpeedInfo(CommProcess):
    '''
        Get network adapter Speed
    '''
    def getStatus(self):
        cmd_get_speed_info = "for e in eth0 eth1; do /usr/sbin/ethtool $e|awk -v e=$e '/Speed/{print e,0+$NF}'; done"
        fd = os.popen(cmd_get_speed_info)
        speed_info_list = fd.readlines()
        fd.close()
        speed_info_dict = {}
        for line in speed_info_list:
            speed_list = line.split()
            speed_info_dict[speed_list[0]] = int(speed_list[1])

        return speed_info_dict


class GnetStats(CommProcess):
    '''
        Network card queuing discipline statistics
    '''
    def getStatus(self):
        cmd_get_info = "tc -s qdisc show"
        re_obj = re.compile(r'dev (\S+) root .*dropped (\d+), overlimits \d+ requeues (\d+)', re.S)
        stats_dict = {}
        try:
            qdisc_out = os.popen(cmd_get_info).read().split('qdisc')
            for s in qdisc_out:
                m = re_obj.search(s)
                if m:
                    dev, dropped, requeues = m.groups()
                    stats_dict[ dev + '_qdisc_dropped'] = dropped
                    stats_dict[ dev + '_qdisc_requeues'] = requeues

        except Exception:
            print traceback.format_exc()
        return stats_dict


class NetSnmp(CommProcess):
    '''
        TODO parse /proc/net/snmp  获取所有公共信息供下面的类使用
    '''
    def getStatus(self):
        snmp_dict = {}
        snmp_lines = open("/proc/net/snmp").readlines()
        sep = re.compile(r'[:\s]+')
        n = 0
        for line in snmp_lines:
            n += 1
            fields = sep.split(line.strip())
            proto = fields.pop(0)
            if n % 2 == 1:
                #header line
                keys = fields
            else:
                #value line
                try:
                    values = [ long(f) for f in fields ]
                except Exception, e:
                    print e
                kv = dict(zip(keys, values))
                proto_dict = snmp_dict.setdefault(proto, {})
                proto_dict.update(kv)
        return snmp_dict


class NetSnmpIpTcpUdp(NetSnmp):
    '''
        Get ip/tcp/udp information from /proc/net/snmp
    '''
    def getStatus(self):
        snmp_dict = super(NetSnmpIpTcpUdp, self).getStatus()
        ret = {}
        ret['TcpInCsumErrors'] = snmp_dict['Tcp'].pop('InCsumErrors', 0)
        ret['UdpInCsumErrors'] = snmp_dict['Udp'].pop('InCsumErrors', 0)
        ret.update(snmp_dict['Tcp'])
        ret.update(snmp_dict['Ip'])
        ret.update(snmp_dict['Udp'])
        icmp_keys = [ 'InDestUnreachs',]
        for key in icmp_keys:
            ret[key] = snmp_dict['Icmp'].get(key, 0)
        return ret

    #需作特殊处理 对数值作额外的处理 (单位)
    def process(self):
        report_dict = {}
        report_dict = super(NetSnmpIpTcpUdp, self).process()
        report_dict['RetransRatio'] = long(report_dict['RetransSegs'] * 100 / report_dict['OutSegs'])
        report_dict['NewEstab'] = report_dict.pop('CurrEstab', 0)
        if report_dict['NewEstab'] > 2147483648:
            report_dict['NewEstab'] = abs(report_dict['NewEstab']-4294967296)
        return report_dict

class SvrTcpCurrEstab(NetSnmp):
    '''
        Get tcp current establish amount
    '''
    def getStatus(self):
        snmp_dict = super(SvrTcpCurrEstab, self).getStatus()
        return { 'CurrEstab' : snmp_dict['Tcp']['CurrEstab'] }



if __name__ == "__main__":
    print "Version Number: %s" % version_num
    start_time = time()
    print "Start Time:%s" % start_time
    #{Object name : dict time ... }
    process_dict = {
            SvrCpuUsage:5,
            SvrSwapUsage:60,
            SvrHdIoRatio:60,
            GnetStats:60,
            NetSnmpIpTcpUdp:60,
            TopCpuUsage:0,
            SvrCpuLoad:0,
            SvrMemUsage:0,
            SvrShmUsage:0,
            SvrPosixShm:0,
            SvrHdUsage:0,
            SvrTcpCurrEstab:0,
            SvrFdInfo:0,
            SvradaptSpeedInfo:0,
            }
    child_pid_list = []
    for key in process_dict.keys():
        try:
            pid = os.fork()
        except OSError:
            sys.exit("Unable to create child process!")
        if pid == 0:
            #new a object with dict time
            my_inst = key(process_dict[key])
            my_inst.report()
            sys.exit(0)
        else:
            child_pid_list.append(pid)

    for pid in child_pid_list:
        os.wait()

    end_time = time()
    run_time = (long(end_time * 10) - long(start_time * 10)) / 10
    print "End   Time:%s" % end_time
    print "Run Time:%ss" % run_time

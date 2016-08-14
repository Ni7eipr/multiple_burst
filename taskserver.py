#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import re
import logging
from multiprocessing.managers import BaseManager
from multiprocessing import Queue
from time import sleep
import threading

class classlog(object):
    """log class"""
    def __init__(self,logfilename="log.txt",level="INFO"):
        level = level if level in ['CRITICAL','ERROR','WARNING','INFO','DEBUG','NOTSET'] else 'INFO'
        self.logger = logging.getLogger("classlog")
        self.logger.setLevel(logging.DEBUG)
        Fileformatter = logging.Formatter("%(asctime)s - %(filename)s - %(levelname)-8s:%(message)s",
        datefmt='%Y-%m-%d %I:%M:%S %p')
        Streamformatter = logging.Formatter("%(asctime)s %(filename)s %(levelname)s:%(message)s",
        datefmt='%Y-%m-%d %I:%M:%S')# ,filename='example.log')

        Filelog = logging.FileHandler(logfilename)
        Filelog.setFormatter(Fileformatter)
        Filelog.setLevel(logging.DEBUG)

        Streamlog = logging.StreamHandler()
        Streamlog.setFormatter(Streamformatter)
        Streamlog.setLevel(level)

        self.logger.addHandler(Filelog)
        self.logger.addHandler(Streamlog)

    def debug(self,msg):
        self.logger.debug(msg)

    def info(self,msg):
        self.logger.info(msg)

    def warn(self,msg):
        self.logger.warn(msg)

    def error(self,msg):
        self.logger.error(msg)

    def critical(self,msg):
        self.logger.critical(msg)


def Argparse():

    parser = argparse.ArgumentParser(usage="%(prog)s [options]",add_help=False,

    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=(u'''
        作者：End1ng blog:end1ng.wordpress.com
        --------------------------------
        分布式弱口令爆破工具
        服务端'''))
    optional = parser.add_argument_group('optional arguments')
    optional.add_argument('-h', '--help', action="store_true", help='help of the %(prog)s program')
    optional.add_argument('--version', action='version', version='%(prog)s 1.1')

    args = parser.add_argument_group('Necessary parameter')

    args.add_argument('-i','--ip', nargs='+',metavar=u'ip',help=u'*目标ip 多个用空格分隔 eg. 127.0.0.1 192.168.1.1-254')

    args.add_argument('-u','--user', nargs='*',metavar=u'姓名',help=u'*用户名 多个用空格分隔')
    args.add_argument('-U','--userfile',metavar=u'文件',help=u'*用户名列表文件')
    args.add_argument('-p','--pass', nargs='*',metavar=u'密码',help=u'*密码 多个用空格分隔')
    args.add_argument('-P','--passfile',metavar=u'文件',help=u'*密码列表文件')
    args.add_argument('-t','--protocol',metavar=u'协议',help=u'需要进行爆破的协议 默认全部:ftp,ssh,telnet,mysql,smb')

    other = parser.add_argument_group('other arguments')
    other.add_argument('--level',metavar=u'level',help=u'程序运行级别:CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET')

    args=parser.parse_args()
    args = vars(args)

    if len(sys.argv) == 1 or args['help']:
        parser.print_help()
        sys.exit()
    if not args['user'] and not args['userfile']:
        LOG.error(u" 请输入账号")
        sys.exit()
    if not args['pass'] and not args['passfile']:
        LOG.error(u" 请输入密码")
        sys.exit()
    if not args['ip']:
        LOG.error(u" 请输入ip")
        sys.exit()

    return args

def getiplist(ipslist):
    iplist = []
    for ips in ipslist:
        try:
            ip = ips.split("-")
            ipstart = int(ip[0].split(".")[-1])
            ipend = int(ip[1])
            ipbase = ".".join(ip[0].split(".")[:3])
            for x in range(ipstart,ipend + 1):
                iplist.append(ipbase + "." + str(x))
        except:
            iplist.append(ips)
    return iplist

def get_result(pid):
    while not ip_queue.empty():
        LOG.info(re_queue.get())
        sleep(2)

    print
    LOG.info(u"任务列表已空 等待获取最终结果。。。。\n")
    sleep(5)

    while not re_queue.empty():
        LOG.info(re_queue.get())
        sleep(2)

    LOG.info(u"结果列表无数据")
    os.kill(pid,9)

LOG = classlog("log.txt","INFO")
ARGS = Argparse()

iplist = []
userlist = []
passlist = []

iplist.extend(getiplist(ARGS['ip']))

if ARGS['user']:
    userlist.extend(ARGS['user'])
elif ARGS['userfile']:
    with open(ARGS['userfile'],"r") as f:
        userlist.extend(f.readlines())

if ARGS['pass']:
    passlist.extend(ARGS['pass'])
elif ARGS['passfile']:
    with open(ARGS['userfile'],"r") as f:
        passlist.extend(f.readlines())

###############################################
# iplist = ["192.168.3.2-238"]
# userlist = []
# passlist = []
# iplist = (getiplist(iplist))
# for x in xrange(1,10):
#     userlist.append("msfadmin")
# passlist.append("msfadmin")
###############################################


ip_queue = Queue()

for x in iplist:
    ip_queue.put(x)
re_queue = Queue()

class QueueManager(BaseManager): pass

QueueManager.register('get_ip_queue', callable=lambda:ip_queue)
QueueManager.register('get_re_queue', callable=lambda:re_queue)
QueueManager.register('get_userlist', callable=lambda:userlist)
QueueManager.register('get_passlist', callable=lambda:passlist)

m = QueueManager(address=('', 50000), authkey='abracadabra')

s = m.get_server()
LOG.info(u"服务器已启动 请运行worker程序\n")

t1 = threading.Thread(target=get_result,args=(os.getpid(),))
t1.start()

s.serve_forever()

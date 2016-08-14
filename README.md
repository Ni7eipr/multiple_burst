# multiple_burst
分布式弱口令扫描

# 用法

## 服务端
```
usage: taskserver.py [options]

        作者：End1ng blog:end1ng.wordpress.com
        --------------------------------
        分布式弱口令爆破工具
        服务端

optional arguments:
  -h, --help            help of the taskserver.py program
  --version             show program's version number and exit

Necessary parameter:
  -i ip [ip ...], --ip ip [ip ...]
                        *目标ip 多个用空格分隔 eg. 127.0.0.1 192.168.1.1-254
  -u [姓名 [姓名 ...]], --user [姓名 [姓名 ...]]
                        *用户名 多个用空格分隔
  -U 文件, --userfile 文件  *用户名列表文件
  -p [密码 [密码 ...]], --pass [密码 [密码 ...]]
                        *密码 多个用空格分隔
  -P 文件, --passfile 文件  *密码列表文件
  -t 协议, --protocol 协议  需要进行爆破的协议 默认全部:ftp,ssh,telnet,mysql,smb

other arguments:
  --level level         程序运行级别:CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET
```

## 客户端
```
./taskworker.py 192.168.0.1
```

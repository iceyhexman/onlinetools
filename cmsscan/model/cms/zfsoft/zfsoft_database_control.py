#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 正方教务系统数据库任意操纵
referer: http://www.wooyun.org/bugs/wooyun-2014-079938
author: Lucifer
description: 端口211数据可操纵，泄露敏感信息。
'''
import sys
import socket
import warnings
from termcolor import cprint
from urllib.parse import urlparse

class zfsoft_database_control_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 211
        if r"http" in self.url:
            #提取host
            host = urlparse(self.url)[1]
            try:
                port = int(host.split(':')[1])
            except:
                pass
            flag = host.find(":")
            if flag != -1:
                host = host[:flag]
        else:
            host = self.url

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        try:
            s.connect((host, port))
            cprint("[+]存在正方教务系统数据库任意操纵漏洞...(高危)\tpayload: "+host+":"+str(port), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = zfsoft_database_control_BaseVerify(sys.argv[1])
    testVuln.run()

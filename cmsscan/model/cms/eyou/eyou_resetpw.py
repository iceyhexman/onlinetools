#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 亿邮邮件系统重置密码问题暴力破解
referer: http://www.wooyun.org/bugs/wooyun-2015-0162892
author: Lucifer
description: 亿邮邮件系统找回密码处，如果用户设置问题密码过于简单可被暴力破解。
'''
import sys
import requests
import warnings
from termcolor import cprint

class eyou_resetpw_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/?q=resetpw"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if req.status_code == 200 and r"pw_intensity" in req.text:
                cprint("[+]存在eyou邮件系统重置密码问题页面...(敏感信息)\tpayload: "+vulnurl, "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = eyou_resetpw_BaseVerify(sys.argv[1])
    testVuln.run()
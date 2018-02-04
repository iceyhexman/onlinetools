#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: git源码泄露扫描
referer: unknown
author: Lucifer
description: 忘记了删除.git目录而导致的漏洞。
'''
import sys
import requests
import warnings
from termcolor import cprint

class git_check_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/.git/config"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"repositoryformatversion" in req.text and req.status_code==200:
                cprint("[+]存在git源码泄露漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = git_check_BaseVerify(sys.argv[1])
    testVuln.run()

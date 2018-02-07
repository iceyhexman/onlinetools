#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS wcm webservice文件写入漏洞
referer: https://www.secpulse.com/archives/18044.html
author: Lucifer
description: 拓尔思wcm系统webservice有两处操作可任意写入webshell。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_wcm_service_writefile_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/wcm/services/trs:templateservicefacade?wsdl"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"writeFile" in req.text and r"writeSpecFile" in req.text:
                cprint("[+]存在拓尔思 wcm webservice文件写入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_wcm_service_writefile_BaseVerify(sys.argv[1])
    testVuln.run()

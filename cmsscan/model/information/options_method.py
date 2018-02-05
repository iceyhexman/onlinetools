#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: options方法开启
referer: unknow
author: Lucifer
description: robots.txt是爬虫标准文件，可从文件里找到屏蔽了哪些爬虫搜索的目录
'''
import sys
import requests
import warnings


class options_method_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        vulnurl = self.url
        try:
            req = requests.options(vulnurl, headers=headers, timeout=10, verify=False)

            if r"OPTIONS" in req.headers['Allow']:
                return "[+]存在options方法开启...(敏感信息)"+"\tpayload: "+vulnurl+"\tAllow:"+req.headers['Allow']
            else:
                return "[-]NO vuln!"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = options_method_BaseVerify(sys.argv[1])
    testVuln.run()
